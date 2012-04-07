/*
 * Copyright (C) 2011 Eduardo José Tagle
 * Copyright (C) 2010 Danijel Posilovic - dan1j3l
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "Sensors"
//#define LOG_NDEBUG 1

#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <math.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/select.h>
#include <linux/input.h>

#include <hardware/hardware.h>
#include <hardware/sensors.h>
#include <cutils/log.h>

/*****************************************************************************/

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/*****************************************************************************/

struct sensors_poll_context_t {
	struct sensors_poll_device_t device; // must be first
	int fd;
	int in_use;	/* if sensor is in use right now */
	int enabled;	/* If sensor is enabled or not */
};

/*****************************************************************************/

// sensor IDs must be a power of two and
// must match values in SensorManager.java
#define EVENT_TYPE_ACCEL_X          ABS_X
#define EVENT_TYPE_ACCEL_Y          ABS_Y
#define EVENT_TYPE_ACCEL_Z          ABS_Z

// 720 LSG = 1G
#define LSG                         (720.0f)

// conversion of acceleration data to SI units (m/s^2)
#define CONVERT_A                   (GRAVITY_EARTH / LSG)
#define CONVERT_A_X                 (-CONVERT_A)
#define CONVERT_A_Y                 (CONVERT_A)
#define CONVERT_A_Z                 (-CONVERT_A)

/*****************************************************************************/

static int open_inputdev(const char* id)
{
	/* scan all input drivers and look for "id" */
	int fd = -1;
	const char *dirname = "/dev/input";
	char devname[PATH_MAX];
	char *filename;
	DIR *dir;
	struct dirent *de;
	
	dir = opendir(dirname);
	if(dir == NULL)
		return -1;
	
	strcpy(devname, dirname);
	filename = devname + strlen(devname);
	*filename++ = '/';
	
	while((de = readdir(dir))) {
		if(de->d_name[0] == '.' &&
				(de->d_name[1] == '\0' ||
					(de->d_name[1] == '.' && de->d_name[2] == '\0')))
		continue;
		
		strcpy(filename, de->d_name);
		
		LOGD("Querying '%s' ...",devname);
		fd = open(devname, O_RDONLY);
		if (fd >= 0) {
			
			char name[80];
			if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), &name) < 1) {
				name[0] = '\0';
			}
			LOGD("Device '%s' is '%s' ... Looking for '%s' ...", devname,name,id);
			if (!strcmp(name, id)) {
				LOGV("using (name=%s)", name);
				break;
			}
			close(fd);
			fd = -1;
		}
	}
	closedir(dir);

	if (fd < 0) {
		LOGE("Couldn't find or open '%s' driver (%s)", id, strerror(errno));
	}
	return fd;
}

static int inc_uses(sensors_poll_context_t* ctx)
{
	if (ctx->in_use == 0) {
		/* Try the original name */
		ctx->fd = open_inputdev("bma150");
	
		/* If we failed, try the alternate name */
		if (ctx->fd == -1)
		    ctx->fd = open_inputdev("accelerometer_tegra");
	    
		if (ctx->fd == -1)
		    return -1;
	}
	
	/* Flag the sensor is in use */
	ctx->in_use++;
	return 0;
}

static int dec_uses(sensors_poll_context_t* ctx)
{
	if (ctx->in_use == 1) {
		close(ctx->fd);
		ctx->fd = -1;
	}
	ctx->in_use --;
	return 0;
}

/*****************************************************************************/

static int poll__activate(struct sensors_poll_device_t *dev, int handle, int enabled)
{
	sensors_poll_context_t *ctx = (sensors_poll_context_t *)dev;
	
	LOGD("activate: %d",enabled);
	
	/* If already in the right state, don't do anything */
	if (ctx->enabled == enabled)
	    return 0;
	
	/* Enable or disable based on the request */
	if (enabled) {
		if (inc_uses(ctx) != 0)
		    return -1;
	} else {
		if (dec_uses(ctx) != 0)
		    return -1;
	}
	
	/* Store the new state */
	ctx->enabled = enabled;
	
	return 0;
}

/*****************************************************************************/

static int poll__close(struct hw_device_t *dev)
{
	struct sensors_poll_context_t* ctx = (struct sensors_poll_context_t*)dev;
	
	LOGD("close");
	
	if (ctx) {
		if (ctx->fd != -1) {
			close(ctx->fd);
			ctx->fd = -1;
		}
		free(ctx);
	}
	return 0;
}

/*****************************************************************************/

static int poll__poll(struct sensors_poll_device_t *dev, sensors_event_t* data, int count)
{
	sensors_poll_context_t *ctx = (sensors_poll_context_t *)dev;
	
//comment out LOGD to stop span in logs, dont need to see poll every second -cass
	//LOGD("poll");
	
	int fd;
	int pos = 0;
	
	if (inc_uses(ctx) != 0) {
	    LOGE("Unable to enable sensor");
	    return -1;
	}
	
	fd = ctx->fd;
	if (fd < 0) {
		LOGE("invalid accelerometer file descriptor, fd=%d", fd);
		return -1;
	}

	memset(data,0,sizeof(*data)*count);
	
	// wait until we get a complete event for an enabled sensor
	while (1) {
		
		/* read the next event */
		struct input_event event;
		int nread;
		fd_set rfds;
		int n;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		n = select(fd + 1, &rfds, NULL, NULL, NULL);
		LOGV("return from select: %d\n", n);
		
		if (n < 0) {
			LOGE("%s: error from select(%d): %s",
			__FUNCTION__, fd, strerror(errno));
			dec_uses(ctx);
			return pos;
		}

		if (FD_ISSET(fd, &rfds)) {
			nread = read(fd, &event, sizeof(event));
			if (nread == sizeof(event)) {
				
				if (event.type == EV_ABS) {
					LOGV("event type: %d code: %d value: %-5d time: %ds",
					event.type, event.code, event.value,(int)event.time.tv_sec);
					
					switch (event.code) {
					case EVENT_TYPE_ACCEL_X:
						data[pos].acceleration.x = event.value * CONVERT_A_X;
						break;
					case EVENT_TYPE_ACCEL_Y:
						data[pos].acceleration.y = event.value * CONVERT_A_Y;
						break;
					case EVENT_TYPE_ACCEL_Z:
						data[pos].acceleration.z = event.value * CONVERT_A_Z;
						break;
					}

				} else
				if (event.type == EV_SYN) {
					data[pos].version = sizeof(sensors_event_t);
					data[pos].sensor = 0;
					data[pos].type = SENSOR_TYPE_ACCELEROMETER;
					data[pos].timestamp = event.time.tv_usec * 1000; // ns
					pos++;
					if (pos >= count)
					dec_uses(ctx);
					return pos;
				}
			}
			else LOGE("read too small %d", nread);
		}
		else LOGV("fd is not set");
	}
}

/*****************************************************************************/

static int poll__set_delay(struct sensors_poll_device_t *dev, int handle, int64_t us)
{
	LOGD("set_delay");
	return 0;
}

/*****************************************************************************/

/** Open a new instance of a sensor device using name */
static int open_sensors(const struct hw_module_t* module, const char* name, struct hw_device_t** device)
{
	struct sensors_poll_context_t *dev;
	
	LOGD("open_sensors");
	
	dev = (struct sensors_poll_context_t *) malloc(sizeof(*dev));
	memset(dev, 0, sizeof(*dev));
	
	dev->fd = -1;
	
	dev->device.common.tag 		= HARDWARE_DEVICE_TAG;
	dev->device.common.version  = 0;
	dev->device.common.module 	= const_cast<hw_module_t*>(module);;
	dev->device.common.close  	= poll__close;
	dev->device.activate 		= poll__activate;
	dev->device.poll 		= poll__poll;
	dev->device.setDelay		= poll__set_delay;
	*device = &dev->device.common;
	return 0;
}

static const struct sensor_t sSensorList[] = {
	{
		name: "BMA150 3-axis Accelerometer",
		vendor: "Bosh",
		version: 1,
		handle: SENSORS_HANDLE_BASE,
		type: SENSOR_TYPE_ACCELEROMETER, 
		maxRange: 4.0f*9.81f, 
		resolution: (4.0f*9.81f)/256.0f, 
		power: 0.2f,
		minDelay: 0,
	},
};

static int sensors__get_sensors_list(struct sensors_module_t* module, struct sensor_t const** list)
{
	LOGD("get_sensors_list");
	
	*list = sSensorList;
	return ARRAY_SIZE(sSensorList);
}

static struct hw_module_methods_t sensors_module_methods = {
	open: open_sensors,
};

/* Must not be const, or the linker will throw the symbol! */
struct sensors_module_t HAL_MODULE_INFO_SYM = {
	common: {
		tag: HARDWARE_MODULE_TAG,
		version_major: 1,
		version_minor: 0,
		id: SENSORS_HARDWARE_MODULE_ID,
		name: "Shuttle Sensor Module",
		author: "The Android Open Source Project",
		methods: &sensors_module_methods,
		dso: 0,
	},
	get_sensors_list: sensors__get_sensors_list,
};

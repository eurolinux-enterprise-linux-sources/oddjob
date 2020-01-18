/*
   Copyright 2005 Red Hat, Inc.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Red Hat, Inc., nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
   OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"
#include <sys/param.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"

struct oddjob_buffer {
	unsigned char *data;
	size_t size, spare, used;
};

struct oddjob_buffer *
oddjob_buffer_new(size_t initial_size)
{
	struct oddjob_buffer *ret;
	ret = malloc(sizeof(struct oddjob_buffer));
	if (initial_size < 1024) {
		initial_size = 1024;
	}
	if (ret != NULL) {
		ret->data = malloc(initial_size);
		if (ret->data != NULL) {
			ret->size = initial_size;
			ret->spare = 0;
			ret->used = 0;
			ret->data[ret->spare + ret->used] = '\0';
		} else {
			free(ret);
			ret = NULL;
		}
	}
	return ret;
}

static void
oddjob_buffer_assure_avail(struct oddjob_buffer *buf, size_t minimum_size)
{
	unsigned char *data;
	size_t would_be_nice;
	if (buf->spare + buf->used + minimum_size > buf->size) {
		would_be_nice = (howmany(buf->spare + buf->used + minimum_size,
					 1024) + 1) * 1024;
		data = malloc(would_be_nice);
		if (data == NULL) {
			fprintf(stderr, "Out of memory\n");
			_exit(1);
		}
		memcpy(data, buf->data, buf->spare + buf->used);
		free(buf->data);
		buf->data = data;
		buf->size = would_be_nice;
	}
}

void
oddjob_buffer_prepend(struct oddjob_buffer *buf,
		      const unsigned char *bytes, size_t length)
{
	if (length == (size_t) -1) {
		length = strlen((const char *)bytes);
	}
	if (buf->spare > length) {
		memcpy(buf->data + buf->spare - length, bytes, length);
		buf->spare -= length;
	} else {
		oddjob_buffer_assure_avail(buf, length + 1);
		memmove(buf->data + buf->spare + length,
			buf->data + buf->spare, buf->used);
		memcpy(buf->data + buf->spare, bytes, length);
		buf->used += length;
	}
}

void
oddjob_buffer_append(struct oddjob_buffer *buf,
	      	     const unsigned char *bytes, size_t length)
{
	if (length == (size_t) -1) {
		length = strlen((const char *)bytes);
	}
	oddjob_buffer_assure_avail(buf, length + 1);
	memmove(buf->data + buf->spare + buf->used, bytes, length);
	buf->used += length;
	buf->data[buf->spare + buf->used] = '\0';
}

void
oddjob_buffer_consume(struct oddjob_buffer *buf, size_t length)
{
	if (length < buf->used) {
		buf->spare += length;
		buf->used -= length;
	} else {
		buf->used = 0;
	}
}

void
oddjob_buffer_clear(struct oddjob_buffer *buf)
{
	buf->used = 0;
}

void
oddjob_buffer_free(struct oddjob_buffer *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->size = 0;
	buf->used = 0;
	buf->spare = 0;
	free(buf);
}

size_t
oddjob_buffer_length(struct oddjob_buffer *buf)
{
	return buf->used;
}

const unsigned char *
oddjob_buffer_data(struct oddjob_buffer *buf)
{
	return buf->data + buf->spare;
}

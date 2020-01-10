/*
 * Copyright 2005 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA
 *
 */

#ifndef oddjob_buffer_h
#define oddjob_buffer_h

#include <sys/types.h>

struct oddjob_buffer;

struct oddjob_buffer *oddjob_buffer_new(size_t initial_size);
void oddjob_buffer_prepend(struct oddjob_buffer *buf,
			   const unsigned char *bytes, size_t length);
void oddjob_buffer_append(struct oddjob_buffer *buf,
			  const unsigned char *bytes, size_t length);
void oddjob_buffer_consume(struct oddjob_buffer *buf, size_t length);
void oddjob_buffer_clear(struct oddjob_buffer *buf);
void oddjob_buffer_free(struct oddjob_buffer *buf);
size_t oddjob_buffer_length(struct oddjob_buffer *buf);
const unsigned char *oddjob_buffer_data(struct oddjob_buffer *buf);

#endif

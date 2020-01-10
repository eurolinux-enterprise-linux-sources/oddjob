/*
   Copyright 2005,2008 Red Hat, Inc.
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
#include <sys/types.h>
#include <stdlib.h>
#include <Python.h>
#include <dbus/dbus.h>
#include "../src/common.h"
#include "../src/oddjob.h"
#include "../src/util.h"

static PyObject *
call_method(PyObject *self, PyObject *args)
{
	const char *service, *object, *interface, *method;
	char output[64 * 1024], errors[64 * 1024];
	char **argv;
	PyObject *ret, *tuple;
	int i, result;

	service = ODDJOB_SERVICE_NAME;
	object = ODDJOB_OBJECT_PATH;
	interface = ODDJOB_INTERFACE_NAME;
	method = "list";
	ret = tuple = NULL;

	if (!PyArg_ParseTuple(args, "ssss|O",
			      &service, &object, &interface, &method,
			      &tuple) != 0) {
		return NULL;
	}
	memset(output, '\0', sizeof(output));
	argv = NULL;
	for (i = 0; (tuple != NULL) && (i < PyTuple_Size(tuple)); i++) {
		oddjob_resize_array((void **) &argv, sizeof(char*),
				    i, i + 2);
		argv[i] = PyString_AsString(PyObject_Str(PyTuple_GetItem(tuple, i)));
	}
	i = oddjob_dbus_call_methodv(DBUS_BUS_SYSTEM,
				     service, object, interface, method,
				     &result,
				     output, sizeof(output),
				     errors, sizeof(errors),
				     argv);
	oddjob_free(argv);
	if (i != 0) {
		PyErr_SetString(PyExc_RuntimeError, errors);
		return NULL;
	}
	return Py_BuildValue("iss", result, output, errors);
}

static PyObject *
default_object(PyObject *self, PyObject *args)
{
	return Py_BuildValue("s", oddjob_dbus_get_default_object());
}

static PyObject *
default_interface(PyObject *self, PyObject *args)
{
	return Py_BuildValue("s", oddjob_dbus_get_default_interface());
}

static PyObject *
default_service(PyObject *self, PyObject *args)
{
	return Py_BuildValue("s", oddjob_dbus_get_default_service());
}

static PyMethodDef oddjobmethods[] = {
	{"call_method", call_method, METH_VARARGS},
	{"default_object", default_object, METH_NOARGS},
	{"default_interface", default_interface, METH_NOARGS},
	{"default_service", default_service, METH_NOARGS},
	{NULL, NULL, 0},
};

void
initoddjob(void)
{
	Py_InitModule(PACKAGE_NAME, oddjobmethods);
}

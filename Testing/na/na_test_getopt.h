/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

/* Original source from h5tools_utils.h */

#ifndef NA_TEST_GETOPT_H
#define NA_TEST_GETOPT_H

/*
 * get_option determines which options are specified on the command line and
 * returns a pointer to any arguments possibly associated with the option in
 * the ``opt_arg'' variable. get_option returns the shortname equivalent of
 * the option. The long options are specified in the following way:
 *
 * struct long_options foo[] = {
 *   { "filename", require_arg, 'f' },
 *   { "append", no_arg, 'a' },
 *   { "width", require_arg, 'w' },
 *   { NULL, 0, 0 }
 * };
 *
 * Long named options can have arguments specified as either:
 *
 *   ``--param=arg'' or ``--param arg''
 *
 * Short named options can have arguments specified as either:
 *
 *   ``-w80'' or ``-w 80''
 *
 * and can have more than one short named option specified at one time:
 *
 *   -aw80
 *
 * in which case those options which expect an argument need to come at the
 * end.
 */
struct na_test_opt {
    const char  *name;     /* name of the long option                */
    int          has_arg;  /* whether we should look for an arg      */
    char         shortval; /* the shortname equivalent of long arg
                            * this gets returned from na_test_getopt */
};

enum {
    no_arg = 0,  /* doesn't take an argument */
    require_arg, /* requires an argument     */
    optional_arg /* argument is optional     */
};

#ifdef __cplusplus
extern "C" {
#endif

extern int na_test_opt_ind_g; /* token pointer */
extern const char *na_test_opt_arg_g; /* flag argument (or value) */

int
na_test_getopt(int argc, char *argv[], const char *opts,
        const struct na_test_opt *l_opts);

#ifdef __cplusplus
}
#endif

#endif /* NA_TEST_GETOPT_H */

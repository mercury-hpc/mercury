Mercury
=======
[![Build status][travis-ci-svg]][travis-ci-link]
[![Latest version][mercury-release-svg]][mercury-release-link]

   Mercury is an RPC framework specifically designed for use in HPC systems
   that allows asynchronous transfer of parameters and execution requests,
   as well as direct support of large data arguments. The network implementation
   is abstracted, allowing easy porting to future systems and efficient use
   of existing native transport mechanisms. Mercury's interface is generic
   and allows any function call to be serialized.

   Please see the accompanying COPYING file for license details.

   Contributions and patches are welcomed but require a Contributor License
   Agreement (CLA) to be filled out. Please contact us if you are interested
   in contributing to Mercury by subscribing to the [mailing lists][mailing-lists].

Architectures supported
=======================

   Architectures supported by MPI implementations are generally supported by the
   network abstraction layer. MPI, BMI (tcp) and SM (shared-memory) plugins
   fully implement the network abstraction layer and are currently supported.
   The CCI plugin is experimental and underlying CCI transport plugins
   (`tcp`, `sm`, `verbs`, `gni`) may require additional testing or fixes.
   The libfabric plugin is experimental and underlying libfabric providers
   (`tcp`, `verbs`, `psm2`, `gni`) may require additional testing or fixes.

   See the [plugin requirements](#plugin-requirements) section for
   plugin requirement details.

Documentation
=============

   Please see the documentation available on the mercury [website][documentation]
   for a quick introduction to Mercury.

Software requirements
=====================

   Compiling and running Mercury requires up-to-date versions of various
   software packages. Beware that using excessively old versions of these
   packages can cause indirect errors that are very difficult to track down.

Plugin requirements
-------------------

To make use of the BMI plugin, please do:

    git clone git://git.mcs.anl.gov/bmi && cd bmi
    # If you are building BMI on a MacOS platform, then apply the following patch:
    # patch -p1 < patches/bmi-osx.patch
    ./prepare && ./configure --enable-shared --enable-bmi-only
    make && make install

To make use of the MPI plugin, Mercury requires a _well-configured_ MPI
implementation (MPICH2 v1.4.1 or higher / OpenMPI v1.6 or higher) with
`MPI_THREAD_MULTIPLE` available on targets that will accept remote
connections. Processes that are _not_ accepting incoming connections are
_not_ required to have a multithreaded level of execution.

To make use of the native NA SM (shared-memory) plugin on Linux,
the cross-memory attach (CMA) feature introduced in kernel v3.2 is required.
The yama security module must also be configured to allow remote process memory
to be accessed (see this [page][yama]). On MacOS, code signing with inclusion of
the na_sm.plist file into the binary is currently required to allow process
memory to be accessed.

To make use of the CCI plugin, please refer to the CCI build instructions
available on this [page][cci].

To make use of the libfabric/OFI plugin, please refer to the libfabric build
instructions available on this [page][libfabric].

Optional requirements
---------------------

For optional automatic code generation features (which are used for generating
serialization and deserialization routines), the preprocessor subset of the
BOOST library must be included (Boost v1.48 or higher is recommended).
The library itself is therefore not necessary since only the header is used.

On Linux OpenPA v1.0.3 or higher is required (the version that is included
with MPICH can also be used) for systems that do not have `stdatomic.h`
(GCC version less than 4.8).

Building
========

If you install the full sources, put the tarball in a directory where you
have permissions (e.g., your home directory) and unpack it:

    gzip -cd mercury-X.tar.gz | tar xvf -

   or

    bzip2 -dc mercury-X.tar.bz2 | tar xvf -

Replace "X" with the version number of the package.

(Optional) If you checked out the sources using git (without the --recursive
option) and want to build the testing suite (which requires the kwsys
submodule) or use checksums (which requires the mchecksum submodule), you need
to issue from the root of the source directory the following command:

    git submodule update --init

Mercury makes use of the CMake build-system and requires that you do an
out-of-source build. In order to do that, you must create a new build
directory and run the 'ccmake' command from it:

    cd mercury-X
    mkdir build
    cd build
    ccmake .. (where ".." is the relative path to the mercury-X directory)

Type 'c' multiple times and choose suitable options. Recommended options are:

    BUILD_SHARED_LIBS                ON (or OFF if the library you link
                                     against requires static libraries)
    BUILD_TESTING                    ON
    Boost_INCLUDE_DIR                /path/to/include/directory
    CMAKE_INSTALL_PREFIX             /path/to/install/directory
    MERCURY_ENABLE_PARALLEL_TESTING  ON/OFF
    MERCURY_USE_BOOST_PP             ON
    MERCURY_USE_CHECKSUMS            ON
    MERCURY_USE_EAGER_BULK           ON
    MERCURY_USE_SYSTEM_MCHECKSUM     ON/OFF
    MERCURY_USE_XDR                  OFF
    NA_USE_BMI                       ON/OFF
    NA_USE_MPI                       ON/OFF
    NA_USE_CCI                       ON/OFF
    NA_USE_OFI                       ON/OFF
    NA_USE_SM                        ON/OFF

Setting include directory and library paths may require you to toggle to
the advanced mode by typing 't'. Once you are done and do not see any
errors, type 'g' to generate makefiles. Once you exit the CMake
configuration screen and are ready to build the targets, do:

    make

(Optional) Verbose compile/build output:

This is done by inserting "VERBOSE=1" in the "make" command. E.g.:

    make VERBOSE=1

Installing
==========

Assuming that the `CMAKE_INSTALL_PREFIX` has been set (see previous step)
and that you have write permissions to the destination directory, do
from the build directory:

     make install

Testing
=======

Tests can be run to check that basic function shipping (metadata and bulk
data transfers) is properly working. CTest is used to run the tests,
simply run from the build directory:

    ctest .

(Optional) Verbose testing:

This is done by inserting `-V` in the `ctest` command.  E.g.:

    ctest -V .

Extra verbose information can be displayed by inserting `-VV`. E.g.:

    ctest -VV .

Tests run with one server process and X client processes. To change the
number of client processes that are being used, the `MPIEXEC_MAX_NUMPROCS`
variable needs to be modified (toggle to advanced mode if you do not see
it). The default value is 2.
Note that you need to run `make` again after the makefile generation
to use the new value. Note also that this variable needs to be changed
if you run the tests manually and use a different number of client
processes.

(Optional) To run the tests manually with the MPI plugin, open up two
terminal windows, one for the server and one for the client. From the same
directory where you have write permissions (so that the port configuration
file can be written by the server and read by the client) do:

    mpirun -np 1 /path/to/binary/hg_test_server -c mpi

and in the other:

    mpirun -np 2 /path/to/binary/hg_test_TESTNAME -c mpi

The same applies to other plugins, do `./hg_test_server -h` for more options.

[mailing-lists]: http://mercury-hpc.github.io/help#mailing-lists
[documentation]: http://mercury-hpc.github.io/documentation/
[cci]: http://cci-forum.com/?page_id=46
[libfabric]: https://github.com/ofiwg/libfabric
[travis-ci-svg]: https://travis-ci.org/mercury-hpc/mercury.svg
[travis-ci-link]: https://travis-ci.org/mercury-hpc/mercury
[mercury-release-svg]: https://img.shields.io/github/release/mercury-hpc/mercury.svg
[mercury-release-link]: https://github.com/mercury-hpc/mercury/releases/latest
[yama]: https://www.kernel.org/doc/Documentation/security/Yama.txt


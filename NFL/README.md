How to use IoT Package on RIOT OS
=======================================================================

Prerequisite
------------
* Installed the RIOT OS enviornment
* Installed the cross-compiling tools for boards

Getting started
------------
To build applications, create environment using the following commands:
```
mkdir riot
cd riot
git clone https://github.com/named-data-iot/RIOT
git clone https://github.com/RoySCU/ndn-riot
```

Afterwards, you can create applications using the module, e.g., based on the template in package-demo repository:
```
git clone https://github.com/RoySCU/ndn-riot/package-demo
cd package-demo
cp -r iot-template <YOUR-APP>
cd <YOUR-APP>
... add necessary files ...
make <FLAGS_REQUIRED>
```
QCDT_FORMAT=1
PAGE_SIZE=2048
PHONE_DTS_FILES=./phone_dts/dt_*.dts
for DTSNAME in $PHONE_DTS_FILES; \
do \
  ./dtc -I dts $DTSNAME -O dtb -o $DTSNAME.dtb; \
done
if [[ $QCDT_FORMAT == 2 ]]; then FMT=-2; else unset FMT; fi;
./dtbToolCM $FMT -o new_dtb.img -s $PAGE_SIZE phone_dts/
rm -rf ./phone_dts/*.dtb

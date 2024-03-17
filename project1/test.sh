ID=521021911101

sudo rmmod calc &> /dev/null
make > /dev/null
sudo insmod calc.ko operand1=2 operand2=1,2,3,4,5 operator=add
cat /proc/$ID/calc

sudo rmmod calc
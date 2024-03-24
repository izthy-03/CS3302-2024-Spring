ID=521021911101

sudo rmmod calc &> /dev/null
make > /dev/null
sudo insmod calc.ko operand1=2 operand2=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 operator=add
cat /proc/$ID/calc

sudo rmmod calc
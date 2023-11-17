cd /home/lubuntu/bf-sde-9.2.0
export SDE=/home/lubuntu/bf-sde-9.2.0
export SDE_INSTALL=/home/lubuntu/bf-sde-9.2.0/install/
export PATH=$SDE_INSALL/bin:$PATH

. /home/lubuntu/tools/set_sde.bash

usage() { echo "Usage: $0 [-p p4_program_name] [-c with/without compile]" 1>&2; exit 1;}

while getopts ":p:c:" flag; do
	case $flag in
		p) p4_program_path=${OPTARG}
		   echo "^^^^^^^^^$p4_program_path^^^^^^^^^^^^";;
		   #exit;;
		c) compile=${OPTARG}
		   echo "^^^^^^^^^^^^^^COMPILE IS $compile^^^^^^^^^^^^^^";;
		   #exit;;
	esac
done
shift $((OPTIND-1))

echo "*******************Running the p4 program $p4_program_path*****************************";

res=$((compile -1))

echo "RES is $res";

if [[ $res -eq 0 ]]; then
	echo "********************Compiling $p4_program_path *******************************"
	#/home/lubuntu/tools/p4_build.sh --with-p4c=bf-p4c $p4_program_path
	compile_output=$(/home/lubuntu/tools/p4_build.sh --with-p4c=bf-p4c $p4_program_path)
        if [[ "$compile_output" == *"Error"* ]]; then
                echo "OUTPUT CONTAINS ERROR ... EXITING"
                exit
        fi
fi



sudo $SDE_INSTALL/bin/veth_setup.sh
#read -p "What is the name of the p4 program (without .p4)" p4_program_name
p4_program_name="$(basename $p4_program_path)"
p4_program_name="${p4_program_name::-3}"

#p4_program_name=${p4_program_name::-3}
#/home/ekfoury/bf-sde-9.2.0/run_tofino_model.sh -p $p4_program_name

# echo "Running $p4_program_name"

# /home/lubuntu/bf-sde-9.2.0/run_switchd.sh -p $p4_program_name


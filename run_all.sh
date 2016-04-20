#! /bin/sh

output_dir=./results

# dtrace requires running as root
if [ $(id -u) -ne 0 ]
then
    echo "This script must be run as root." 1>&2
    exit 1
fi

finish() {
    to_kill="$(jobs -p)"
    # the nginx script doesn't seem to be killing properly. Why?
    kill  $to_kill || echo "Could not kill pids: " $to_kill

    # nothing makes sure all the files end with ]

    sleep 1
    # if processes didn't die, or other dtrace are running, notify
    echo ""
    echo "remaining dtrace processes:"
    echo "-------------"
    ps aux | grep [d]trace
    echo "-------------"
}
trap finish SIGINT

mkdir -p $output_dir

while true
do
    # watch for postgres, and make sure we're dtracing all postgres processes
    # Does postgres actually require the pid? It definitely throws an error if
    # run when no postgres is running.
    curr_postgres=$(pgrep postgres)
    if [ $? == 0 ]
    then
        for postgres in $(pgrep postgres)
        do
            pgrep -f 'dtrace.*postgres.*$postgres' || ./postgres.d $postgres > $output_dir/postgres.json
        done
    fi

    # watch for nginx, and make sure we're dtracing all nginx processes
    curr_nginx=$(pgrep nginx)
    if [ $? == 0 ]
    then
        for nginx in $(pgrep nginx)
        do
            pgrep -f 'dtrace.*nginx.*$nginx' || ./nginx.d -p $nginx > $output_dir/nginx.json
        done
    fi
    sleep 5
done &
loop_pid=$!


#
# events_script.d takes 2 arguments - ppids to filter out
# This lets us avoid recording events generated directly by this script
#
echo "Storing results in " $output_dir
./events_script.d $$ $loop_pid > $output_dir/events.json &
./gitserver.d > $output_dir/gitserver.json &


echo "Waiting... (Ctrl+C to stop)"

wait


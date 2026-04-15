RESULTS_DIR="$(cd "$(dirname "$0")/../.." && pwd)/results"
mkdir -p "$RESULTS_DIR"
CSV="$RESULTS_DIR/spotify_tui-no-ifc.csv"

echo "compile_time,run_time" > "$CSV"

for i in {1..100}; do
  echo -n "Run $i/100: "

  sleep 0.5

  # Clean, then measure compile time
  cargo clean >/dev/null 2>&1

  compile_time=$( (time cargo build >/dev/null 2>&1) 2>&1 | grep real | awk '{print $2}' | sed 's/[ms]//g' | awk -F: '{ if (NF==2) print ($1 * 60) + $2; else print $1 }' )

  # Already compiled — run with EOF on stdin so it prints the board then exits
  run_time=$( (time cargo run < /dev/null >/dev/null 2>&1) 2>&1 | grep real | awk '{print $2}' | sed 's/[ms]//g' | awk -F: '{ if (NF==2) print ($1 * 60) + $2; else print $1 }' )

  if [ -z "$compile_time" ] || [ -z "$run_time" ]; then
    echo "Error on run $i"
  else
    echo "compile=${compile_time}s  run=${run_time}s"
    echo "$compile_time,$run_time" >> "$CSV"
  fi
done

echo -e "\n--- Results saved to $CSV ---"

echo -e "\n--- Median Compile Time ---"
awk -F, 'NR>1 {print $1}' "$CSV" | sort -n | awk '{a[i++]=$1} END {
  if (i == 0) print "No data collected";
  else if (i % 2 == 1) print a[int(i/2)] " seconds";
  else print (a[i/2-1] + a[i/2]) / 2 " seconds"
}'

echo -e "\n--- Median Run Time ---"
awk -F, 'NR>1 {print $2}' "$CSV" | sort -n | awk '{a[i++]=$1} END {
  if (i == 0) print "No data collected";
  else if (i % 2 == 1) print a[int(i/2)] " seconds";
  else print (a[i/2-1] + a[i/2]) / 2 " seconds"
}'

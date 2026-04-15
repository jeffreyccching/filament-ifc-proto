# Clear any old temp files
> .times.txt

for i in {1..100}; do
  echo -n "Run $i/100: "
  
  # 1. Force kill any hung cargo metadata processes (optional but safer)
  # 2. Wait a brief moment for file locks to clear
  sleep 0.5
  
  cargo clean >/dev/null 2>&1
  
  # Capture the 'real' time
  # This logic handles both 4.897s and 1m4.897s formats
  real_time=$( (time cargo build >/dev/null 2>&1) 2>&1 | grep real | awk '{print $2}' | sed 's/[ms]//g' | awk -F: '{ if (NF==2) print ($1 * 60) + $2; else print $1 }' )
  
  if [ -z "$real_time" ]; then
    echo "Error on run $i"
  else
    echo "$real_time s"
    echo "$real_time" >> .times.txt
  fi
done

echo -e "\n--- Median Real Build Time ---"
sort -n .times.txt | awk '{a[i++]=$1} END {
  if (i == 0) print "No data collected";
  else if (i % 2 == 1) print a[int(i/2)] " seconds"; 
  else print (a[i/2-1] + a[i/2]) / 2 " seconds"
}'
rm .times.txt
#!/bin/bash
echo "Running using trace:"
cat ${TRACE_FILE} 
cat ${TRACE_FILE} | ./scenario

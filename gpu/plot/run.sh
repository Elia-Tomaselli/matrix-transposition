#!/bin/bash

srun --job-name=matrix-transposition --nodes=1 --ntasks=1 --cpus-per-task=1 --gres=gpu:1 --partition=edu5 $1 $2

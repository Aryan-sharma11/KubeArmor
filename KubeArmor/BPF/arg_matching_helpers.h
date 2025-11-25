/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2024 Authors of KubeArmor */
/* This module contains the common structures shared by lsm and system monitor*/
#include "common_types.h"
#ifndef __ARG_MATCHING_HELPERS_H
#define __ARG_MATCHING_HELPERS_H
#define MAX_ENTRIES 10240
#define MAX_ARGUMENT_SIZE 256
// #define MAX_PATH_SIZE 256

// struct for argument string
struct argVal
{
    char argsArray[MAX_ARGUMENT_SIZE];
};

// key for kubearmor_args_store map (tgid + argument index)
struct cmd_args_key
{
    u64 tgid;
    u64 ind;
};

// map to store arguments for a process
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct cmd_args_key);
    __type(value, struct argVal);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_args_store SEC(".maps");

// map to store argument string -- created to avoid memory overflow in verifier
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct argVal); // Store the args in this struct
} cmd_args_buf SEC(".maps");

// structs for argument matching
// typedef struct argsOuterkey
// {
//     struct outer_key okey;
//     char path[MAX_PATH_SIZE];
// } argsOuterkey;
// typedef struct argsInnerkey
// {
//     char source[MAX_PATH_SIZE];
//     char arg[MAX_PATH_SIZE];
// } argsInnerkey;

//-- Maps structs for argument matching----//
// argument matching

// Key for argument map => okey+bufkey+argname

// struct {
//     __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
//     __type(key, u32);
//     __type(value, arg_bufs_k);
//     __uint(max_entries, 1);
// } args_bufk SEC(".maps");
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 10240);
//     __type(key, arg_bufs_k);  // Composite key of okey+bufkey+argname
//     __type(value, u8);            // Value is a u8 integer
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
// } kubearmor_arguments SEC(".maps");

// struct kubearmor_args_outer_hash
// {
//     __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//     __uint(max_entries, 1000);
//     __uint(key_size, sizeof(struct argsOuterkey));
//     __uint(value_size, sizeof(u32));
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
// } kubearmor_arguments SEC(".maps");
// //--------------------------------------------//

#endif /* __ARG_MATCHING_HELPERS_H */
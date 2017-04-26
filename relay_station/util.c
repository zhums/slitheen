/* Name: util.c
 *
 * This file contains safe wrappers for common functions and implementations of
 * data structures
 *
 * Slitheen - a decoy routing system for censorship resistance
 * Copyright (C) 2017 Cecylia Bocovich (cbocovic@uwaterloo.ca)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 * 
 * If you modify this Program, or any covered work, by linking or combining
 * it with the OpenSSL library (or a modified version of that library), 
 * containing parts covered by the terms of the OpenSSL Licence and the
 * SSLeay license, the licensors of this Program grant you additional
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of the OpenSSL library used as well as that of the covered
 * work.
 */



#include <stdio.h>
#include <stdlib.h>
#include "util.h"

//malloc macro that exits on error
void *emalloc(size_t size){
    void *ptr = malloc(size);
    if (ptr == NULL){
        fprintf(stderr, "Memory failure. Exiting...\n");
	exit(1);
    }

    return ptr;
}

//calloc macro that exits on error
void *ecalloc(size_t nmemb, size_t size){
    void *ptr = calloc(nmemb, size);
    if(ptr == NULL){
        fprintf(stderr, "Memory failure. Exiting...\n");
        exit(1);
    }

    return ptr;
}

/**
 * Initializes a generic queue structure
 */

queue *init_queue(){
    queue *new_queue = emalloc(sizeof(queue));

    new_queue->first = NULL;
    new_queue->last = NULL;

    return new_queue;
}

/**
 * Function to append a struct to the end of a list
 */
void enqueue(queue *list, void *data){
    //Do not allow appending NULL data
    if(data == NULL){
        return;
    }
    element *new_elem = emalloc(sizeof(element));
    new_elem->data = data;
    new_elem->next = NULL;

    if(list->first == NULL){
        list->first = new_elem;
        list->last = new_elem;
    } else {
        list->last->next = new_elem;
        list->last = new_elem;
    }

}

/**
 * Removes and returns the first element from the front of the list. Returns NULL
 * if list is empty
 */
void *dequeue(queue *list){

    if(list->first == NULL){
        return NULL;
    }

    void *data = list->first->data;
    element *target =list->first;
    
    list->first = target->next;

    free(target);

    return data;
}

/**
 * Returns the nth element of the queue (as provided)
 *
 * An input of -1 peeks at last element
 *
 * Returns data on success, NULL on failure
 */

void *peek(queue *list, int32_t n){
    
    int32_t i;
    element *target = list->first;

    if(n == -1){
        target = list->last;
    }

    for(i=0; (i< n) && (target == NULL); i++){
        target = target->next;
    }

    if(target == NULL){
        return NULL;
    } else {
        return target->data;
    }

}

/**
 * Removes (frees the data in) all elements from the list and then frees the list itself
 */
void remove_queue(queue *list){

    void *data = dequeue(list);
    while(data != NULL){
        free(data);
        data = dequeue(list);
    
    }
    
    free(list);
}


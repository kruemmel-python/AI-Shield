#pragma once

#include "ai_shield_driver_protocol.h"

#define AI_SHIELD_EVENT_QUEUE_CAPACITY 256U

typedef struct _AI_SHIELD_EVENT_QUEUE {
    KSPIN_LOCK Lock;
    ULONG ReadIndex;
    ULONG WriteIndex;
    ULONG Count;
    ULONGLONG NextSequence;
    AI_SHIELD_DRIVER_EVENT Events[AI_SHIELD_EVENT_QUEUE_CAPACITY];
} AI_SHIELD_EVENT_QUEUE;

static void AiShieldEventQueueInitialize(AI_SHIELD_EVENT_QUEUE* queue) {
    KeInitializeSpinLock(&queue->Lock);
    queue->ReadIndex = 0;
    queue->WriteIndex = 0;
    queue->Count = 0;
    queue->NextSequence = 1;
}

static BOOLEAN AiShieldEventQueuePush(AI_SHIELD_EVENT_QUEUE* queue, AI_SHIELD_DRIVER_EVENT* event) {
    KIRQL oldIrql;
    BOOLEAN accepted = FALSE;
    KeAcquireSpinLock(&queue->Lock, &oldIrql);
    if (queue->Count < AI_SHIELD_EVENT_QUEUE_CAPACITY) {
        event->Version = AI_SHIELD_PROTOCOL_VERSION;
        event->Size = sizeof(*event);
        event->Sequence = queue->NextSequence++;
        queue->Events[queue->WriteIndex] = *event;
        queue->WriteIndex = (queue->WriteIndex + 1U) % AI_SHIELD_EVENT_QUEUE_CAPACITY;
        ++queue->Count;
        accepted = TRUE;
    }
    KeReleaseSpinLock(&queue->Lock, oldIrql);
    return accepted;
}

static BOOLEAN AiShieldEventQueuePop(AI_SHIELD_EVENT_QUEUE* queue, AI_SHIELD_DRIVER_EVENT* event) {
    KIRQL oldIrql;
    BOOLEAN available = FALSE;
    KeAcquireSpinLock(&queue->Lock, &oldIrql);
    if (queue->Count != 0U) {
        *event = queue->Events[queue->ReadIndex];
        queue->ReadIndex = (queue->ReadIndex + 1U) % AI_SHIELD_EVENT_QUEUE_CAPACITY;
        --queue->Count;
        available = TRUE;
    }
    KeReleaseSpinLock(&queue->Lock, oldIrql);
    return available;
}

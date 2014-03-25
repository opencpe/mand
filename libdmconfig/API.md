# DM API - **DRAFT**

# Sessions

* read-only session for reading and getting change notifications/event
* one read-write session (with idle/timeout support) for active configurations
* no concurrent write access!

# Notifications

API clients can request notification no changes with either specific value
or entire subtree granularity.
Notification can be active or passive (polled).

# Events

Events are the result of/triggered by value changes and are send after the
change notification (strict ordering).
Event dependencies exist (when on event is triggered this other event is also
triggered). These dependencies form a ordered graph and are always send in a
defined sequence with multiple phases (pre, main, post).

# Protocol

* bi-directional request-reply (RPC)

* requests to mand:
 - Start Session
 - Switch Session
 - Commit
 - Cancel
 - Subscribe Notify
 - Unsubscribe Notify
 - Param Notify
 - Recursive Param Notify
 - Get Passive Notifications
 - Add Instance
 - Del Instance
 - Set
 - Get
 - List
 - Find

* requests from mand
 - Get

* events from mand
 - Parameter Change Notify
 - Event Broadcast

## Commands to mand

### Start Session

start a new read-only sessions

### Switch Session

change between read-only and read-write access

### Commit

commit current pending changes (only permited in r/w state)

### Cancel

discard current pending changes

### Subscribe Notify

Allocate a subscription slot identifier. The identifier is to be used with
all other notification commands.

### Unsubscribe Notify

Cancels all parameter notifications for a specific notification identifier.

### Param Notify

Add a single value change notification to a specific indentifier. Parameter is
specified by path.

### Recursive Param Notify

Add value change notifications to all values in a subtree to a specific indentifier.

### Get Passive Notifications

Poll pending notifications as list of structures with element type, name, value

### Add Instance

Add a new instance of a subtree (only permited in r/w state)

### Del Instance

Delete a specific instance of a subtree (only permited in r/w state)

### Set

Set a value (only permited in r/w state)

### Get

Get a value

### List

Fetch all items at specific tree level

### Find

Find a specific subtree instance by key

## Requests from mand

### Get

Get a value specified by path

## Events from mand

### Parameter Change Notify

List of structures with element type, name, value that have changed

### Event Broadcast

Broadcast a single event

## Argument Encoding

* every argument is encoded with a type specifier
* exact (binary) argument type and string is supported for every type
* string arguments are converted to binary representation by DM,
  conversion failure is reported as error
* types:
  - string
  - octets (binary string)
  - (u)int 8, 16, 32 64 bit
  - MAC
  - IP(v4/v6)
  - ticks (1/10 seconds)

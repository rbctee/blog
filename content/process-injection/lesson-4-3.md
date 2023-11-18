Title: Lesson 4.3 - APC Injection
Date: 2022-11-13T15:04:35.000Z
Status: Draft


## Theory

### Asynchronous Procedure Calls

One way to perform process injection is to leverage `Asynchronous Procedure Calls` (APC). According to the official documentation provided by Microsoft:

<blockquote>An **asynchronous procedure call** (APC) is a function that executes asynchronously in the context of a particular thread.</blockquote><blockquote>When an APC is queued to a thread, the system issues a software interrupt.</blockquote><blockquote>The next time the thread is scheduled, it will run the APC function. An APC generated by the system is called a `kernel-mode` APC.</blockquote><blockquote>An APC generated by an application is called a `user-mode` APC.</blockquote><blockquote>A thread must be in an alertable state to run a user-mode APC.</blockquote>There two key points in this description:

<ol><li>**each thread has a queue for APC calls**, so you can add an APC call to a specific thread of a specific process if you have the required privileges
- for the APC to be executed, the thread must be in an **alertable state**

There are different functions you can use to force a thread to enter an `alertable state`:

<blockquote>A thread enters an alertable state when it calls the `SleepEx`, `SignalObjectAndWait`, `MsgWaitForMultipleObjectsEx`, `WaitForMultipleObjectsEx`, or `WaitForSingleObjectEx` function.</blockquote><blockquote>If the wait is satisfied before the APC is queued, the thread is no longer in an alertable wait state so the APC function will not be executed.</blockquote>
### QueueUserAPC

You can use the function `QueueUserAPC` in order to add an APC the queue of a specific thread:

<blockquote>An application queues an APC to a thread by calling the **QueueUserAPC** function.</blockquote><blockquote>The calling thread specifies the address of an APC function in the call to QueueUserAPC.</blockquote><blockquote>The queuing of an APC is a request for the thread to call the APC function.</blockquote>Let's look at the function definition for a moment:

```cpp
DWORD QueueUserAPC(
    [in] PAPCFUNC  pfnAPC,
    [in] HANDLE    hThread,
    [in] ULONG_PTR dwData
);
```

As you can see, it uses three parameters:

- **pfnAPC**, a pointer to an APC function (whose code resides inside the memory of the victim process)
- **hThread**, a handle to the victim thread
- **dwData**, a value passed to the APC function

It's important to bear in mind that the code of the function, e.g. the shellcode we want to execute, must reside in the memory of the victim process.

If we wanted, for example, to execute the shellcode for a reverse shell or an implant, first we would need to use a write primitive in order to copy the shellcode inside the victim process.

After that, we could use the `QueueUserAPC` function to add the APC call to the queue of the interested thread.

### Alertable state

As mentioned previously, a process enters an `alertable state` after it calls the following functions:

- `SleepEx`
- `SignalObjectAndWait`
- `MsgWaitForMultipleObjectsEx`
- `WaitForMultipleObjectsEx`
- `WaitForSingleObjectEx`

An alternative is to use the Native API of Windows, in particular the syscall `NtAlertThread`.

## Practice

Here's the final code:

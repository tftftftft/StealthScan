# StealthScan

Project: Automated Malware Scanning Platform
Overview

This project aims to provide an automated platform for scanning malware. Users upload a suspicious file, which then gets executed in various virtual machine environments, each running a different antivirus solution. The user then receives results from all these environments.
How It Works

    The user accesses the web interface and uploads a file for scanning.
    The user is redirected to the payment system (Coinbase) for making payment.
    Once the payment is confirmed, the backend server saves the necessary details and adds a scan job to the job queue.
    A worker node (an available virtual machine among a pool of VMs) picks up the job from the queue, clones a fresh VM from a pre-configured Windows 7 image, and executes the file.
    The worker node records the screen of the VM during the file execution.
    After the scan is completed, the scan results and the screen recording are sent back to the user.

Tech Stack

    Frontend: React.js
    Backend: FastApi, Actix
    Database: PostgreSQL
    Job Queue: RabbitMQ
    Virtualization Platform: ESXi
    Payment Api: Coinbase, Stripe?

Development Plan

    Phase 1: Develop the frontend and backend. Implement the file upload feature and integrate with the Coinbase payment system.

    Phase 2: Set up the ESXi server and create a pool of VMs. Develop the functionality to clone VMs from a pre-configured Windows 7 image.

    Phase 3: Implement the job queue using RabbitMQ. Develop the worker nodes to pick up jobs from the queue, execute the file in a VM, and record the screen.

    Phase 4: Enable the worker nodes to send back the scan results and screen recording to the user.

    Phase 5: Test the entire system end-to-end and fix any issues.

    Phase 6: Deploy the system and monitor for any issues.

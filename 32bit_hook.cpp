#include <stdio.h>
#include <Windows.h>
#include <memoryapi.h>
#include <stdint.h>

void loadLib()
{
	printf("Called loadLib()\n");
	Beep(200, 300);
	return;
}

void HookPayload()
{
	printf("Called HookPayload()\n");
	Beep(500, 300);
	return;
}

int main()
{
	// beep - pre hook
	printf("Beep1.\n");
	loadLib();

	// Virtualprotect saves the old permissions for a piece of memory, so lets shove it into oldProtect.
	// Not used in this example, but if something is expecting RW and gets RWE, you're in for a bad time 
	DWORD oldProtect;

	// Need 5 bytes for our payload 
	VirtualProtect(loadLib, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// jmp 00 00 00 00
	uint8_t payload[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	// Address of HookPayload - Address of target function + shellcode
	// tl;dr The address of our HookPayload function is some odd amount of bytes away from our loadLib function.
	printf("Address of loadLib: %d\n", (uint32_t)loadLib);
	printf("Address of HookPayload: %d\n", (uint32_t)HookPayload);
	uint32_t relAddr = (uint32_t)HookPayload - ((uint32_t)loadLib + sizeof(payload));
	printf("Offset: %d\n", relAddr);

	// After finding the offset, let's modify our Payload to contain the address we'd like to target (e.g, the offset)
	memcpy(payload + 1, &relAddr, 4);

	// Now that we have our payload constructed let's just yolo our payload over the contents initially stored at loadLib
	memcpy(loadLib, payload, sizeof(payload));

	printf("Beep2.\n");
	loadLib();
	
	return 0;
}
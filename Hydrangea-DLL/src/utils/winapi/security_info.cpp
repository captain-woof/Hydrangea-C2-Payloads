#include <Windows.h>
#include "utils/winapi.h"
#include "utils/string_aggregator.h"

/*
SID to DOMAIN/USERNAME

Returned double-pointers point to buffers that must be manually freed
*/
void WinApiCustom::SidToUsernameCustom(IN PSID pSid, OUT LPVOID *ppUserName, OUT LPVOID *ppDomainName)
{
	// Lookup user with above found SID
	DWORD userNameSize = 0;
	DWORD domainNameSize = 0;
	SID_NAME_USE sidNameUse;
	this->loadedFunctions.LookupAccountSidA(
		NULL,
		pSid,
		NULL,
		&userNameSize,
		NULL,
		&domainNameSize,
		&sidNameUse);
	if (userNameSize == 0 || domainNameSize == 0)
		return;

	*ppUserName = this->HeapAllocCustom(userNameSize);
	*ppDomainName = this->HeapAllocCustom(domainNameSize);
	if (*ppUserName == NULL || *ppDomainName == NULL)
	{
		if (*ppUserName != NULL)
			this->HeapFreeCustom(*ppUserName);
		if (*ppDomainName != NULL)
			this->HeapFreeCustom(*ppDomainName);

		*ppUserName = NULL;
		*ppDomainName = NULL;
		return;
	}

	this->loadedFunctions.LookupAccountSidA(
		NULL,
		pSid,
		(LPSTR)*ppUserName,
		&userNameSize,
		(LPSTR)*ppDomainName,
		&domainNameSize,
		&sidNameUse);
}

/*
Converts AccessMask to AccessMaskCustom structure

objectType: Type of object whose AccessMask is to be parsed
accessMask: Access mask of object
pAccessMaskCustom: Pointer to a ACCESS_MASK_CUSTOM that receives output
*/
void WinApiCustom::AccessMaskToAccessMaskCustom(IN SECURABLE_OBJECT_TYPE_CUSTOM objectType, IN ACCESS_MASK accessMask, OUT PACCESS_MASK_CUSTOM pAccessMaskCustom)
{
	// Zero-out access mask custom
	RtlZeroMemoryCustom((PBYTE)pAccessMaskCustom, sizeof(ACCESS_MASK_CUSTOM));

	// Generic rights
	if ((accessMask & GENERIC_ALL) == GENERIC_ALL)
		pAccessMaskCustom->GenericAll = 1;
	if ((accessMask & GENERIC_READ) == GENERIC_READ)
		pAccessMaskCustom->GenericRead = 1;
	if ((accessMask & GENERIC_WRITE) == GENERIC_WRITE)
		pAccessMaskCustom->GenericWrite = 1;
	if ((accessMask & GENERIC_EXECUTE) == GENERIC_EXECUTE)
		pAccessMaskCustom->GenericExecute = 1;

	// Standard rights
	if ((accessMask & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL)
		pAccessMaskCustom->StandardAll = 1;
	if ((accessMask & READ_CONTROL) == READ_CONTROL)
		pAccessMaskCustom->ReadControl = 1;
	if ((accessMask & SYNCHRONIZE) == SYNCHRONIZE)
		pAccessMaskCustom->Synchronize = 1;
	if ((accessMask & WRITE_DAC) == WRITE_DAC)
		pAccessMaskCustom->WriteDac = 1;
	if ((accessMask & WRITE_OWNER) == WRITE_OWNER)
		pAccessMaskCustom->WriteOwner = 1;
	if ((accessMask & DELETE) == DELETE)
		pAccessMaskCustom->Delete = 1;

	// Specific rights - files & directories
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::FILE_OBJ || objectType == SECURABLE_OBJECT_TYPE_CUSTOM::DIRECTORY)
	{
		if ((accessMask & FILE_READ_EA) == FILE_READ_EA)
			pAccessMaskCustom->FileReadEA = 1;
		if ((accessMask & FILE_WRITE_EA) == FILE_WRITE_EA)
			pAccessMaskCustom->FileWriteEA = 1;
		if ((accessMask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
			pAccessMaskCustom->FileReadAttributes = 1;
		if ((accessMask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
			pAccessMaskCustom->FileWriteAttributes = 1;
	}

	// Specific rights - files
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::FILE_OBJ)
	{
		if ((accessMask & FILE_READ_DATA) == FILE_READ_DATA)
			pAccessMaskCustom->FileReadData = 1;
		if ((accessMask & FILE_WRITE_DATA) == FILE_WRITE_DATA)
			pAccessMaskCustom->FileWriteData = 1;
		if ((accessMask & FILE_APPEND_DATA) == FILE_APPEND_DATA)
			pAccessMaskCustom->FileAppendData = 1;
		if ((accessMask & FILE_EXECUTE) == FILE_EXECUTE)
			pAccessMaskCustom->FileExecute = 1;
	}

	// Specific rights - directories
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::DIRECTORY)
	{
		if ((accessMask & FILE_LIST_DIRECTORY) == FILE_LIST_DIRECTORY)
			pAccessMaskCustom->FileListDirectory = 1;
		if ((accessMask & FILE_ADD_FILE) == FILE_ADD_FILE)
			pAccessMaskCustom->FileAddFile = 1;
		if ((accessMask & FILE_ADD_SUBDIRECTORY) == FILE_ADD_SUBDIRECTORY)
			pAccessMaskCustom->FileAddSubdirectory = 1;
		if ((accessMask & FILE_TRAVERSE) == FILE_TRAVERSE)
			pAccessMaskCustom->FileTraverse = 1;
		if ((accessMask & FILE_DELETE_CHILD) == FILE_DELETE_CHILD)
			pAccessMaskCustom->FileDeleteChild = 1;
	}

	// Specific rights - file mapping object
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::FILE_MAPPING_OBJECT)
	{
		if ((accessMask & FILE_MAP_ALL_ACCESS) == FILE_MAP_ALL_ACCESS)
			pAccessMaskCustom->FileMapAllAccess = 1;
		if ((accessMask & FILE_MAP_EXECUTE) == FILE_MAP_EXECUTE)
			pAccessMaskCustom->FileMapExecute = 1;
		if ((accessMask & FILE_MAP_READ) == FILE_MAP_READ)
			pAccessMaskCustom->FileMapRead = 1;
		if ((accessMask & FILE_MAP_WRITE) == FILE_MAP_WRITE)
			pAccessMaskCustom->FileMapWrite = 1;
	}

	// Specific rights - processes
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::PROCESS)
	{
		if ((accessMask & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
			pAccessMaskCustom->ProcessAllAccess = 1;
		if ((accessMask & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS)
			pAccessMaskCustom->ProcessCreateProcess = 1;
		if ((accessMask & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
			pAccessMaskCustom->ProcessCreateThread = 1;
		if ((accessMask & PROCESS_QUERY_INFORMATION) == PROCESS_QUERY_INFORMATION)
			pAccessMaskCustom->ProcessQueryInformation = 1;
		if ((accessMask & PROCESS_QUERY_LIMITED_INFORMATION) == PROCESS_QUERY_LIMITED_INFORMATION)
			pAccessMaskCustom->ProcessQueryLimitedInformation = 1;
		if ((accessMask & PROCESS_SET_INFORMATION) == PROCESS_SET_INFORMATION)
			pAccessMaskCustom->ProcessSetInformation = 1;
		if ((accessMask & PROCESS_SET_QUOTA) == PROCESS_SET_QUOTA)
			pAccessMaskCustom->ProcessSetQuota = 1;
		if ((accessMask & PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME)
			pAccessMaskCustom->ProcessSuspendResume = 1;
		if ((accessMask & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			pAccessMaskCustom->ProcessTerminate = 1;
		if ((accessMask & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			pAccessMaskCustom->ProcessVmOperation = 1;
		if ((accessMask & PROCESS_VM_READ) == PROCESS_VM_READ)
			pAccessMaskCustom->ProcessVmRead = 1;
		if ((accessMask & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			pAccessMaskCustom->ProcessVmWrite = 1;
	}

	// Specific rights - thread
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::THREAD)
	{
		if ((accessMask & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
			pAccessMaskCustom->ThreadAllAccess = 1;
		if ((accessMask & THREAD_DIRECT_IMPERSONATION) == THREAD_DIRECT_IMPERSONATION)
			pAccessMaskCustom->ThreadDirectImpersonation = 1;
		if ((accessMask & THREAD_GET_CONTEXT) == THREAD_GET_CONTEXT)
			pAccessMaskCustom->ThreadGetContext = 1;
		if ((accessMask & THREAD_IMPERSONATE) == THREAD_IMPERSONATE)
			pAccessMaskCustom->ThreadImpersonate = 1;
		if ((accessMask & THREAD_QUERY_INFORMATION) == THREAD_QUERY_INFORMATION)
			pAccessMaskCustom->ThreadQueryInformation = 1;
		if ((accessMask & THREAD_QUERY_LIMITED_INFORMATION) == THREAD_QUERY_LIMITED_INFORMATION)
			pAccessMaskCustom->ThreadQueryLimitedInformation = 1;
		if ((accessMask & THREAD_SET_CONTEXT) == THREAD_SET_CONTEXT)
			pAccessMaskCustom->ThreadSetContext = 1;
		if ((accessMask & THREAD_SET_INFORMATION) == THREAD_SET_INFORMATION)
			pAccessMaskCustom->ThreadSetInformation = 1;
		if ((accessMask & THREAD_SET_LIMITED_INFORMATION) == THREAD_SET_LIMITED_INFORMATION)
			pAccessMaskCustom->ThreadSetLimitedInformation = 1;
		if ((accessMask & THREAD_SET_THREAD_TOKEN) == THREAD_SET_THREAD_TOKEN)
			pAccessMaskCustom->ThreadSetThreadToken = 1;
		if ((accessMask & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
			pAccessMaskCustom->ThreadSuspendResume = 1;
		if ((accessMask & THREAD_TERMINATE) == THREAD_TERMINATE)
			pAccessMaskCustom->ThreadTerminate = 1;
	}

	// Specific rights - service control manager
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::SC_MANAGER)
	{
		if ((accessMask & SC_MANAGER_ALL_ACCESS) == SC_MANAGER_ALL_ACCESS)
			pAccessMaskCustom->ScManagerAllAccess = 1;
		if ((accessMask & SC_MANAGER_CREATE_SERVICE) == SC_MANAGER_CREATE_SERVICE)
			pAccessMaskCustom->ScManagerCreateService = 1;
		if ((accessMask & SC_MANAGER_CONNECT) == SC_MANAGER_CONNECT)
			pAccessMaskCustom->ScManagerConnect = 1;
		if ((accessMask & SC_MANAGER_ENUMERATE_SERVICE) == SC_MANAGER_ENUMERATE_SERVICE)
			pAccessMaskCustom->ScManagerEnumerateService = 1;
		if ((accessMask & SC_MANAGER_LOCK) == SC_MANAGER_LOCK)
			pAccessMaskCustom->ScManagerLock = 1;
		if ((accessMask & SC_MANAGER_MODIFY_BOOT_CONFIG) == SC_MANAGER_MODIFY_BOOT_CONFIG)
			pAccessMaskCustom->ScManagerModifyBootConfig = 1;
		if ((accessMask & SC_MANAGER_QUERY_LOCK_STATUS) == SC_MANAGER_QUERY_LOCK_STATUS)
			pAccessMaskCustom->ScManagerQueryLockStatus = 1;
	}

	// Specific rights - service
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::SERVICE)
	{
		if ((accessMask & SERVICE_ALL_ACCESS) == SERVICE_ALL_ACCESS)
			pAccessMaskCustom->ServiceAllAccess = 1;
		if ((accessMask & SERVICE_CHANGE_CONFIG) == SERVICE_CHANGE_CONFIG)
			pAccessMaskCustom->ServiceChangeConfig = 1;
		if ((accessMask & SERVICE_ENUMERATE_DEPENDENTS) == SERVICE_ENUMERATE_DEPENDENTS)
			pAccessMaskCustom->ServiceEnumerateDepedents = 1;
		if ((accessMask & SERVICE_INTERROGATE) == SERVICE_INTERROGATE)
			pAccessMaskCustom->ServiceInterrogate = 1;
		if ((accessMask & SERVICE_PAUSE_CONTINUE) == SERVICE_PAUSE_CONTINUE)
			pAccessMaskCustom->ServicePauseContinue = 1;
		if ((accessMask & SERVICE_QUERY_CONFIG) == SERVICE_QUERY_CONFIG)
			pAccessMaskCustom->ServiceQueryConfig = 1;
		if ((accessMask & SERVICE_QUERY_STATUS) == SERVICE_QUERY_STATUS)
			pAccessMaskCustom->ServiceQueryStatus = 1;
		if ((accessMask & SERVICE_START) == SERVICE_START)
			pAccessMaskCustom->ServiceStart = 1;
		if ((accessMask & SERVICE_STOP) == SERVICE_STOP)
			pAccessMaskCustom->ServiceStop = 1;
		if ((accessMask & SERVICE_USER_DEFINED_CONTROL) == SERVICE_USER_DEFINED_CONTROL)
			pAccessMaskCustom->ServiceUserDefinedControl = 1;
	}

	// Specific rights - registry
	if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::REGISTRY)
	{
		{
			if ((accessMask & KEY_ALL_ACCESS) == KEY_ALL_ACCESS)
				pAccessMaskCustom->KeyAllAccess = 1;
			if ((accessMask & KEY_CREATE_LINK) == KEY_CREATE_LINK)
				pAccessMaskCustom->KeyCreateLink = 1;
			if ((accessMask & KEY_CREATE_SUB_KEY) == KEY_CREATE_SUB_KEY)
				pAccessMaskCustom->KeyCreateSubKey = 1;
			if ((accessMask & KEY_ENUMERATE_SUB_KEYS) == KEY_ENUMERATE_SUB_KEYS)
				pAccessMaskCustom->KeyEnumerateSubKeys = 1;
			if ((accessMask & KEY_EXECUTE) == KEY_EXECUTE)
				pAccessMaskCustom->KeyExecute = 1;
			if ((accessMask & KEY_NOTIFY) == KEY_NOTIFY)
				pAccessMaskCustom->KeyNotify = 1;
			if ((accessMask & KEY_QUERY_VALUE) == KEY_QUERY_VALUE)
				pAccessMaskCustom->KeyQueryValue = 1;
			if ((accessMask & KEY_READ) == KEY_READ)
				pAccessMaskCustom->KeyRead = 1;
			if ((accessMask & KEY_SET_VALUE) == KEY_SET_VALUE)
				pAccessMaskCustom->KeySetValue = 1;
			if ((accessMask & KEY_WOW64_32KEY) == KEY_WOW64_32KEY)
				pAccessMaskCustom->KeyWow6432Key = 1;
			if ((accessMask & KEY_WOW64_64KEY) == KEY_WOW64_64KEY)
				pAccessMaskCustom->KeyWow6464Key = 1;
			if ((accessMask & KEY_WRITE) == KEY_WRITE)
				pAccessMaskCustom->KeyWrite = 1;
		}

		// Specific rights - access token
		if (objectType == SECURABLE_OBJECT_TYPE_CUSTOM::ACCESS_TOKEN)
		{
			if ((accessMask & TOKEN_ALL_ACCESS) == TOKEN_ALL_ACCESS)
				pAccessMaskCustom->TokenAllAccess = 1;
			if ((accessMask & TOKEN_ADJUST_DEFAULT) == TOKEN_ADJUST_DEFAULT)
				pAccessMaskCustom->TokenAdjustDefault = 1;
			if ((accessMask & TOKEN_ADJUST_GROUPS) == TOKEN_ADJUST_GROUPS)
				pAccessMaskCustom->TokenAdjustGroups = 1;
			if ((accessMask & TOKEN_ADJUST_PRIVILEGES) == TOKEN_ADJUST_PRIVILEGES)
				pAccessMaskCustom->TokenAdjustPrivileges = 1;
			if ((accessMask & TOKEN_ADJUST_SESSIONID) == TOKEN_ADJUST_SESSIONID)
				pAccessMaskCustom->TokenAdjustSessionId = 1;
			if ((accessMask & TOKEN_ASSIGN_PRIMARY) == TOKEN_ASSIGN_PRIMARY)
				pAccessMaskCustom->TokenAssignPrimary = 1;
			if ((accessMask & TOKEN_DUPLICATE) == TOKEN_DUPLICATE)
				pAccessMaskCustom->TokenDuplicate = 1;
			if ((accessMask & TOKEN_EXECUTE) == TOKEN_EXECUTE)
				pAccessMaskCustom->TokenExecute = 1;
			if ((accessMask & TOKEN_IMPERSONATE) == TOKEN_IMPERSONATE)
				pAccessMaskCustom->TokenImpersonate = 1;
			if ((accessMask & TOKEN_QUERY) == TOKEN_QUERY)
				pAccessMaskCustom->TokenQuery = 1;
			if ((accessMask & TOKEN_QUERY_SOURCE) == TOKEN_QUERY_SOURCE)
				pAccessMaskCustom->TokenQuerySource = 1;
			if ((accessMask & TOKEN_READ) == TOKEN_READ)
				pAccessMaskCustom->TokenRead = 1;
			if ((accessMask & TOKEN_WRITE) == TOKEN_WRITE)
				pAccessMaskCustom->TokenWrite = 1;
		}
	}
}

/*
Gets and parses Security descriptor of an Object by its Handle

hResource: Handle to the object
objectType: Type of object whose Security information is to be fetched
pSecurityInfoCustom: Pointer to a `SECURITY_INFO_CUSTOM`; the containing `pAcesCustom` is a pointer to array of `acesNum` number of `ACE_CUSTOM`, and this must be manually freed
*/
void WinApiCustom::GetObjectSecurityInfoCustom(IN HANDLE hResource, IN SECURABLE_OBJECT_TYPE_CUSTOM objectType, OUT PSECURITY_INFO_CUSTOM pSecurityInfoCustom)
{
	// Get SE_OBJECT_TYPE
	SE_OBJECT_TYPE seObjectType;
	switch (objectType)
	{
	case SECURABLE_OBJECT_TYPE_CUSTOM::FILE_OBJ:
		seObjectType = SE_OBJECT_TYPE::SE_FILE_OBJECT;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::DIRECTORY:
		seObjectType = SE_OBJECT_TYPE::SE_FILE_OBJECT;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::ACCESS_TOKEN:
		seObjectType = SE_OBJECT_TYPE::SE_KERNEL_OBJECT;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::FILE_MAPPING_OBJECT:
		seObjectType = SE_OBJECT_TYPE::SE_KERNEL_OBJECT;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::PROCESS:
		seObjectType = SE_OBJECT_TYPE::SE_KERNEL_OBJECT;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::REGISTRY:
		seObjectType = SE_OBJECT_TYPE::SE_REGISTRY_KEY;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::SC_MANAGER:
		seObjectType = SE_OBJECT_TYPE::SE_SERVICE;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::SERVICE:
		seObjectType = SE_OBJECT_TYPE::SE_SERVICE;
		break;
	case SECURABLE_OBJECT_TYPE_CUSTOM::THREAD:
		seObjectType = SE_OBJECT_TYPE::SE_KERNEL_OBJECT;
		break;
	default:
		return;
	};

	// Get owner, group and DACL
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	PSID pSidOwner = NULL;
	PSID pSidGroup = NULL;
	PACL pDacl = NULL;
	this->loadedFunctions.GetSecurityInfo(
		hResource,
		seObjectType,
		DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
		&pSidOwner,
		&pSidGroup,
		&pDacl,
		NULL,
		&pSecurityDescriptor);
	if (pSecurityDescriptor == NULL)
		goto CLEANUP;

	CopyBuffer(&(pSecurityInfoCustom->sidOwner), pSidOwner, sizeof(SID));
	CopyBuffer(&(pSecurityInfoCustom->sidGroup), pSidGroup, sizeof(SID));

	// Get DACL header, and parse it
	WORD aclSize = pDacl->AclSize;
	pSecurityInfoCustom->acesNum = pDacl->AceCount;

	// Iterate over all ACEs
	PACE_HEADER pAceHeader = (PACE_HEADER)((PBYTE)(pDacl) + sizeof(ACL));

	pSecurityInfoCustom->pAcesCustom = (PACE_CUSTOM)(this->HeapAllocCustom(
		sizeof(ACE_CUSTOM) * pSecurityInfoCustom->acesNum));
	if (pSecurityInfoCustom->pAcesCustom == NULL)
		goto CLEANUP;

	WORD aceIndex = 0;
	PACCESS_MASK pAccessMask = NULL;
	PSID pSidTrustee = NULL;
	BOOL allowed = FALSE;

	while ((PBYTE)pAceHeader != ((PBYTE)(pDacl) + aclSize))
	{
		// According to ACE type, parse it and get access to AccessMask, Trustee, and Allowed/Denied
		switch (pAceHeader->AceType)
		{
		case ACCESS_ALLOWED_ACE_TYPE:
			pAccessMask = &(((PACCESS_ALLOWED_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_ALLOWED_ACE)pAceHeader)->SidStart);
			allowed = TRUE;
			break;
		case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
			pAccessMask = &(((PACCESS_ALLOWED_OBJECT_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_ALLOWED_OBJECT_ACE)pAceHeader)->SidStart);
			allowed = TRUE;
			break;
		case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
			pAccessMask = &(((PACCESS_ALLOWED_CALLBACK_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_ALLOWED_CALLBACK_ACE)pAceHeader)->SidStart);
			allowed = TRUE;
			break;
		case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
			pAccessMask = &(((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_ALLOWED_CALLBACK_OBJECT_ACE)pAceHeader)->SidStart);
			allowed = TRUE;
			break;
		case ACCESS_DENIED_ACE_TYPE:
			pAccessMask = &(((PACCESS_DENIED_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_DENIED_ACE)pAceHeader)->SidStart);
			allowed = FALSE;
			break;
		case ACCESS_DENIED_OBJECT_ACE_TYPE:
			pAccessMask = &(((PACCESS_DENIED_OBJECT_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_DENIED_OBJECT_ACE)pAceHeader)->SidStart);
			allowed = FALSE;
			break;
		case ACCESS_DENIED_CALLBACK_ACE_TYPE:
			pAccessMask = &(((PACCESS_DENIED_CALLBACK_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_DENIED_CALLBACK_ACE)pAceHeader)->SidStart);
			allowed = FALSE;
			break;
		case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
			pAccessMask = &(((PACCESS_DENIED_CALLBACK_OBJECT_ACE)pAceHeader)->Mask);
			pSidTrustee = &(((PACCESS_DENIED_CALLBACK_OBJECT_ACE)pAceHeader)->SidStart);
			allowed = FALSE;
			break;
		default:
			break;
		}

		// Store above found information in custom ACE structure
		if (pAccessMask != NULL && pSidTrustee != NULL)
		{
			// Store SID
			CopyBuffer(&(pSecurityInfoCustom->pAcesCustom[aceIndex].sidTrustee), pSidTrustee, sizeof(SID));

			// Store AccessMask
			this->AccessMaskToAccessMaskCustom(objectType, *pAccessMask, &(pSecurityInfoCustom->pAcesCustom[aceIndex].accessMask));

			// Access/Denied
			pSecurityInfoCustom->pAcesCustom[aceIndex].allowed = allowed;

			// Reset ACE variables
			pAccessMask = NULL;
			pSidTrustee = NULL;
		}

		// Move to next ACE
		aceIndex++;
		pAceHeader = (PACE_HEADER)((PBYTE)pAceHeader + pAceHeader->AceSize);
	}

CLEANUP:
	if (pSecurityDescriptor != NULL)
		this->loadedFunctions.LocalFree(pSecurityDescriptor);
}

/*
Get a file's security information

pSecurityInfoCustom->pAcesCustom must be manually freed
*/
void WinApiCustom::GetFileSecurityInformationCustom(IN PCHAR filePath, OUT PSECURITY_INFO_CUSTOM pSecurityInfoCustom)
{
	HANDLE hFile = NULL;

	// Open handle to file
	hFile = this->loadedFunctions.CreateFileA(
		filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == NULL)
		goto CLEANUP;

	// Get security information of file
	this->GetObjectSecurityInfoCustom(hFile, SECURABLE_OBJECT_TYPE_CUSTOM::FILE_OBJ, pSecurityInfoCustom);

CLEANUP:
	if (hFile != NULL)
		this->loadedFunctions.CloseHandle(hFile);
}

/*
Parses a SECURITY_INFO_CUSTOM and turns it into a human-readable string

ppSecurityInfoCustomDescribed is a double-pointer to the output buffer; must be manually freed
*/
void WinApiCustom::DescribeSecurityInfoCustom(IN PSECURITY_INFO_CUSTOM pSecurityInfoCustom, OUT CHAR **ppSecurityInfoCustomDescribed)
{
	/*
	OWNER: OWNER_NAME
	GROUP: GROUP_NAME
	DACL:
		- TRUSTEE_NAME (ALLOWED): RIGHT1, RIGHT2, ...
		- TRUSTEE_NAME (DENIED): RIGHT1, RIGHT2, ...
	*/
	StringAggregator stringAggregator = StringAggregator(this, FALSE);
	*ppSecurityInfoCustomDescribed = NULL;

	// Prepare strings
	static CHAR commaChar[] = ",";
	static CHAR strOWNER[STRING_OWNER_LEN + 1] = ""; // "OWNER"
	DeobfuscateUtf8String(
		(PCHAR)STRING_OWNER,
		STRING_OWNER_LEN,
		strOWNER);
	static CHAR strGROUP[STRING_GROUP_LEN + 1] = ""; // "GROUP"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GROUP,
		STRING_GROUP_LEN,
		strGROUP);
	static CHAR strDACL[STRING_DACL_LEN + 1] = ""; // "DACL"
	DeobfuscateUtf8String(
		(PCHAR)STRING_DACL,
		STRING_DACL_LEN,
		strDACL);
	static CHAR strALLOWED[STRING_ALLOWED_LEN + 1] = ""; // "ALLOWED"
	DeobfuscateUtf8String(
		(PCHAR)STRING_ALLOWED,
		STRING_ALLOWED_LEN,
		strALLOWED);
	static CHAR strDENIED[STRING_DENIED_LEN + 1] = ""; // "DENIED"
	DeobfuscateUtf8String(
		(PCHAR)STRING_DENIED,
		STRING_DENIED_LEN,
		strDENIED);
	static CHAR strGenericAll[STRING_RIGHTS_GENERIC_ALL_LEN + 1] = ""; // "GenericAll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_GENERIC_ALL,
		STRING_RIGHTS_GENERIC_ALL_LEN,
		strGenericAll);
	static CHAR strGenericRead[STRING_RIGHTS_GENERIC_READ_LEN + 1] = ""; // "GenericRead"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_GENERIC_READ,
		STRING_RIGHTS_GENERIC_READ_LEN,
		strGenericRead);
	static CHAR strGenericWrite[STRING_RIGHTS_GENERIC_WRITE_LEN + 1] = ""; // "GenericWrite"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_GENERIC_WRITE,
		STRING_RIGHTS_GENERIC_WRITE_LEN,
		strGenericWrite);
	static CHAR strGenericExecute[STRING_RIGHTS_GENERIC_EXECUTE_LEN + 1] = ""; // "GenericExecute"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_GENERIC_EXECUTE,
		STRING_RIGHTS_GENERIC_EXECUTE_LEN,
		strGenericExecute);
	static CHAR strStandardAll[STRING_RIGHTS_STANDARD_ALL_LEN + 1] = ""; // "StandardAll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_STANDARD_ALL,
		STRING_RIGHTS_STANDARD_ALL_LEN,
		strStandardAll);
	static CHAR strDelete[STRING_RIGHTS_DELETE_LEN + 1] = ""; // "Delete"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_DELETE,
		STRING_RIGHTS_DELETE_LEN,
		strDelete);
	static CHAR strReadControl[STRING_RIGHTS_READ_CONTROL_LEN + 1] = ""; // "ReadControl"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_READ_CONTROL,
		STRING_RIGHTS_READ_CONTROL_LEN,
		strReadControl);
	static CHAR strWriteDac[STRING_RIGHTS_WRITE_DAC_LEN + 1] = ""; // "WriteDac"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_WRITE_DAC,
		STRING_RIGHTS_WRITE_DAC_LEN,
		strWriteDac);
	static CHAR strWriteOwner[STRING_RIGHTS_WRITE_OWNER_LEN + 1] = ""; // "WriteOwner"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_WRITE_OWNER,
		STRING_RIGHTS_WRITE_OWNER_LEN,
		strWriteOwner);
	static CHAR strSynchronize[STRING_RIGHTS_SYNCHRONIZE_LEN + 1] = ""; // "Synchronize"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SYNCHRONIZE,
		STRING_RIGHTS_SYNCHRONIZE_LEN,
		strSynchronize);
	static CHAR strFileReadEA[STRING_RIGHTS_FILE_READ_E_A_LEN + 1] = ""; // "FileReadEA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_READ_E_A,
		STRING_RIGHTS_FILE_READ_E_A_LEN,
		strFileReadEA);
	static CHAR strFileWriteEA[STRING_RIGHTS_FILE_WRITE_E_A_LEN + 1] = ""; // "FileWriteEA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_WRITE_E_A,
		STRING_RIGHTS_FILE_WRITE_E_A_LEN,
		strFileWriteEA);
	static CHAR strFileReadAttributes[STRING_RIGHTS_FILE_READ_ATTRIBUTES_LEN + 1] = ""; // "FileReadAttributes"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_READ_ATTRIBUTES,
		STRING_RIGHTS_FILE_READ_ATTRIBUTES_LEN,
		strFileReadAttributes);
	static CHAR strFileWriteAttributes[STRING_RIGHTS_FILE_WRITE_ATTRIBUTES_LEN + 1] = ""; // "FileWriteAttributes"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_WRITE_ATTRIBUTES,
		STRING_RIGHTS_FILE_WRITE_ATTRIBUTES_LEN,
		strFileWriteAttributes);
	static CHAR strFileReadData[STRING_RIGHTS_FILE_READ_DATA_LEN + 1] = ""; // "FileReadData"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_READ_DATA,
		STRING_RIGHTS_FILE_READ_DATA_LEN,
		strFileReadData);
	static CHAR strFileWriteData[STRING_RIGHTS_FILE_WRITE_DATA_LEN + 1] = ""; // "FileWriteData"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_WRITE_DATA,
		STRING_RIGHTS_FILE_WRITE_DATA_LEN,
		strFileWriteData);
	static CHAR strFileAppendData[STRING_RIGHTS_FILE_APPEND_DATA_LEN + 1] = ""; // "FileAppendData"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_APPEND_DATA,
		STRING_RIGHTS_FILE_APPEND_DATA_LEN,
		strFileAppendData);
	static CHAR strFileExecute[STRING_RIGHTS_FILE_EXECUTE_LEN + 1] = ""; // "FileExecute"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_EXECUTE,
		STRING_RIGHTS_FILE_EXECUTE_LEN,
		strFileExecute);
	static CHAR strFileListDirectory[STRING_RIGHTS_FILE_LIST_DIRECTORY_LEN + 1] = ""; // "FileListDirectory"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_LIST_DIRECTORY,
		STRING_RIGHTS_FILE_LIST_DIRECTORY_LEN,
		strFileListDirectory);
	static CHAR strFileAddFile[STRING_RIGHTS_FILE_ADD_FILE_LEN + 1] = ""; // "FileAddFile"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_ADD_FILE,
		STRING_RIGHTS_FILE_ADD_FILE_LEN,
		strFileAddFile);
	static CHAR strFileAddSubdirectory[STRING_RIGHTS_FILE_ADD_SUBDIRECTORY_LEN + 1] = ""; // "FileAddSubdirectory"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_ADD_SUBDIRECTORY,
		STRING_RIGHTS_FILE_ADD_SUBDIRECTORY_LEN,
		strFileAddSubdirectory);
	static CHAR strFileTraverse[STRING_RIGHTS_FILE_TRAVERSE_LEN + 1] = ""; // "FileTraverse"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_TRAVERSE,
		STRING_RIGHTS_FILE_TRAVERSE_LEN,
		strFileTraverse);
	static CHAR strFileDeleteChild[STRING_RIGHTS_FILE_DELETE_CHILD_LEN + 1] = ""; // "FileDeleteChild"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_DELETE_CHILD,
		STRING_RIGHTS_FILE_DELETE_CHILD_LEN,
		strFileDeleteChild);
	static CHAR strFileMapAllAccess[STRING_RIGHTS_FILE_MAP_ALL_ACCESS_LEN + 1] = ""; // "FileMapAllAccess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_MAP_ALL_ACCESS,
		STRING_RIGHTS_FILE_MAP_ALL_ACCESS_LEN,
		strFileMapAllAccess);
	static CHAR strFileMapExecute[STRING_RIGHTS_FILE_MAP_EXECUTE_LEN + 1] = ""; // "FileMapExecute"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_MAP_EXECUTE,
		STRING_RIGHTS_FILE_MAP_EXECUTE_LEN,
		strFileMapExecute);
	static CHAR strFileMapRead[STRING_RIGHTS_FILE_MAP_READ_LEN + 1] = ""; // "FileMapRead"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_MAP_READ,
		STRING_RIGHTS_FILE_MAP_READ_LEN,
		strFileMapRead);
	static CHAR strFileMapWrite[STRING_RIGHTS_FILE_MAP_WRITE_LEN + 1] = ""; // "FileMapWrite"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_FILE_MAP_WRITE,
		STRING_RIGHTS_FILE_MAP_WRITE_LEN,
		strFileMapWrite);
	static CHAR strProcessAllAccess[STRING_RIGHTS_PROCESS_ALL_ACCESS_LEN + 1] = ""; // "ProcessAllAccess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_ALL_ACCESS,
		STRING_RIGHTS_PROCESS_ALL_ACCESS_LEN,
		strProcessAllAccess);
	static CHAR strProcessCreateProcess[STRING_RIGHTS_PROCESS_CREATE_PROCESS_LEN + 1] = ""; // "ProcessCreateProcess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_CREATE_PROCESS,
		STRING_RIGHTS_PROCESS_CREATE_PROCESS_LEN,
		strProcessCreateProcess);
	static CHAR strProcessCreateThread[STRING_RIGHTS_PROCESS_CREATE_THREAD_LEN + 1] = ""; // "ProcessCreateThread"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_CREATE_THREAD,
		STRING_RIGHTS_PROCESS_CREATE_THREAD_LEN,
		strProcessCreateThread);
	static CHAR strProcessQueryInformation[STRING_RIGHTS_PROCESS_QUERY_INFORMATION_LEN + 1] = ""; // "ProcessQueryInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_QUERY_INFORMATION,
		STRING_RIGHTS_PROCESS_QUERY_INFORMATION_LEN,
		strProcessQueryInformation);
	static CHAR strProcessQueryLimitedInformation[STRING_RIGHTS_PROCESS_QUERY_LIMITED_INFORMATION_LEN + 1] = ""; // "ProcessQueryLimitedInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_QUERY_LIMITED_INFORMATION,
		STRING_RIGHTS_PROCESS_QUERY_LIMITED_INFORMATION_LEN,
		strProcessQueryLimitedInformation);
	static CHAR strProcessSetInformation[STRING_RIGHTS_PROCESS_SET_INFORMATION_LEN + 1] = ""; // "ProcessSetInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_SET_INFORMATION,
		STRING_RIGHTS_PROCESS_SET_INFORMATION_LEN,
		strProcessSetInformation);
	static CHAR strProcessSetQuota[STRING_RIGHTS_PROCESS_SET_QUOTA_LEN + 1] = ""; // "ProcessSetQuota"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_SET_QUOTA,
		STRING_RIGHTS_PROCESS_SET_QUOTA_LEN,
		strProcessSetQuota);
	static CHAR strProcessSuspendResume[STRING_RIGHTS_PROCESS_SUSPEND_RESUME_LEN + 1] = ""; // "ProcessSuspendResume"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_SUSPEND_RESUME,
		STRING_RIGHTS_PROCESS_SUSPEND_RESUME_LEN,
		strProcessSuspendResume);
	static CHAR strProcessTerminate[STRING_RIGHTS_PROCESS_TERMINATE_LEN + 1] = ""; // "ProcessTerminate"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_TERMINATE,
		STRING_RIGHTS_PROCESS_TERMINATE_LEN,
		strProcessTerminate);
	static CHAR strProcessVmOperation[STRING_RIGHTS_PROCESS_VM_OPERATION_LEN + 1] = ""; // "ProcessVmOperation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_VM_OPERATION,
		STRING_RIGHTS_PROCESS_VM_OPERATION_LEN,
		strProcessVmOperation);
	static CHAR strProcessVmRead[STRING_RIGHTS_PROCESS_VM_READ_LEN + 1] = ""; // "ProcessVmRead"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_VM_READ,
		STRING_RIGHTS_PROCESS_VM_READ_LEN,
		strProcessVmRead);
	static CHAR strProcessVmWrite[STRING_RIGHTS_PROCESS_VM_WRITE_LEN + 1] = ""; // "ProcessVmWrite"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_PROCESS_VM_WRITE,
		STRING_RIGHTS_PROCESS_VM_WRITE_LEN,
		strProcessVmWrite);
	static CHAR strThreadAllAccess[STRING_RIGHTS_THREAD_ALL_ACCESS_LEN + 1] = ""; // "ThreadAllAccess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_ALL_ACCESS,
		STRING_RIGHTS_THREAD_ALL_ACCESS_LEN,
		strThreadAllAccess);
	static CHAR strThreadDirectImpersonation[STRING_RIGHTS_THREAD_DIRECT_IMPERSONATION_LEN + 1] = ""; // "ThreadDirectImpersonation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_DIRECT_IMPERSONATION,
		STRING_RIGHTS_THREAD_DIRECT_IMPERSONATION_LEN,
		strThreadDirectImpersonation);
	static CHAR strThreadGetContext[STRING_RIGHTS_THREAD_GET_CONTEXT_LEN + 1] = ""; // "ThreadGetContext"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_GET_CONTEXT,
		STRING_RIGHTS_THREAD_GET_CONTEXT_LEN,
		strThreadGetContext);
	static CHAR strThreadImpersonate[STRING_RIGHTS_THREAD_IMPERSONATE_LEN + 1] = ""; // "ThreadImpersonate"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_IMPERSONATE,
		STRING_RIGHTS_THREAD_IMPERSONATE_LEN,
		strThreadImpersonate);
	static CHAR strThreadQueryInformation[STRING_RIGHTS_THREAD_QUERY_INFORMATION_LEN + 1] = ""; // "ThreadQueryInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_QUERY_INFORMATION,
		STRING_RIGHTS_THREAD_QUERY_INFORMATION_LEN,
		strThreadQueryInformation);
	static CHAR strThreadQueryLimitedInformation[STRING_RIGHTS_THREAD_QUERY_LIMITED_INFORMATION_LEN + 1] = ""; // "ThreadQueryLimitedInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_QUERY_LIMITED_INFORMATION,
		STRING_RIGHTS_THREAD_QUERY_LIMITED_INFORMATION_LEN,
		strThreadQueryLimitedInformation);
	static CHAR strThreadSetContext[STRING_RIGHTS_THREAD_SET_CONTEXT_LEN + 1] = ""; // "ThreadSetContext"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_SET_CONTEXT,
		STRING_RIGHTS_THREAD_SET_CONTEXT_LEN,
		strThreadSetContext);
	static CHAR strThreadSetInformation[STRING_RIGHTS_THREAD_SET_INFORMATION_LEN + 1] = ""; // "ThreadSetInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_SET_INFORMATION,
		STRING_RIGHTS_THREAD_SET_INFORMATION_LEN,
		strThreadSetInformation);
	static CHAR strThreadSetLimitedInformation[STRING_RIGHTS_THREAD_SET_LIMITED_INFORMATION_LEN + 1] = ""; // "ThreadSetLimitedInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_SET_LIMITED_INFORMATION,
		STRING_RIGHTS_THREAD_SET_LIMITED_INFORMATION_LEN,
		strThreadSetLimitedInformation);
	static CHAR strThreadSetThreadToken[STRING_RIGHTS_THREAD_SET_THREAD_TOKEN_LEN + 1] = ""; // "ThreadSetThreadToken"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_SET_THREAD_TOKEN,
		STRING_RIGHTS_THREAD_SET_THREAD_TOKEN_LEN,
		strThreadSetThreadToken);
	static CHAR strThreadSuspendResume[STRING_RIGHTS_THREAD_SUSPEND_RESUME_LEN + 1] = ""; // "ThreadSuspendResume"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_SUSPEND_RESUME,
		STRING_RIGHTS_THREAD_SUSPEND_RESUME_LEN,
		strThreadSuspendResume);
	static CHAR strThreadTerminate[STRING_RIGHTS_THREAD_TERMINATE_LEN + 1] = ""; // "ThreadTerminate"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_THREAD_TERMINATE,
		STRING_RIGHTS_THREAD_TERMINATE_LEN,
		strThreadTerminate);
	static CHAR strScManagerAllAccess[STRING_RIGHTS_SC_MANAGER_ALL_ACCESS_LEN + 1] = ""; // "ScManagerAllAccess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SC_MANAGER_ALL_ACCESS,
		STRING_RIGHTS_SC_MANAGER_ALL_ACCESS_LEN,
		strScManagerAllAccess);
	static CHAR strScManagerCreateService[STRING_RIGHTS_SC_MANAGER_CREATE_SERVICE_LEN + 1] = ""; // "ScManagerCreateService"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SC_MANAGER_CREATE_SERVICE,
		STRING_RIGHTS_SC_MANAGER_CREATE_SERVICE_LEN,
		strScManagerCreateService);
	static CHAR strScManagerConnect[STRING_RIGHTS_SC_MANAGER_CONNECT_LEN + 1] = ""; // "ScManagerConnect"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SC_MANAGER_CONNECT,
		STRING_RIGHTS_SC_MANAGER_CONNECT_LEN,
		strScManagerConnect);
	static CHAR strScManagerEnumerateService[STRING_RIGHTS_SC_MANAGER_ENUMERATE_SERVICE_LEN + 1] = ""; // "ScManagerEnumerateService"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SC_MANAGER_ENUMERATE_SERVICE,
		STRING_RIGHTS_SC_MANAGER_ENUMERATE_SERVICE_LEN,
		strScManagerEnumerateService);
	static CHAR strScManagerLock[STRING_RIGHTS_SC_MANAGER_LOCK_LEN + 1] = ""; // "ScManagerLock"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SC_MANAGER_LOCK,
		STRING_RIGHTS_SC_MANAGER_LOCK_LEN,
		strScManagerLock);
	static CHAR strScManagerModifyBootConfig[STRING_RIGHTS_SC_MANAGER_MODIFY_BOOT_CONFIG_LEN + 1] = ""; // "ScManagerModifyBootConfig"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SC_MANAGER_MODIFY_BOOT_CONFIG,
		STRING_RIGHTS_SC_MANAGER_MODIFY_BOOT_CONFIG_LEN,
		strScManagerModifyBootConfig);
	static CHAR strScManagerQueryLockStatus[STRING_RIGHTS_SC_MANAGER_QUERY_LOCK_STATUS_LEN + 1] = ""; // "ScManagerQueryLockStatus"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SC_MANAGER_QUERY_LOCK_STATUS,
		STRING_RIGHTS_SC_MANAGER_QUERY_LOCK_STATUS_LEN,
		strScManagerQueryLockStatus);
	static CHAR strServiceAllAccess[STRING_RIGHTS_SERVICE_ALL_ACCESS_LEN + 1] = ""; // "ServiceAllAccess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_ALL_ACCESS,
		STRING_RIGHTS_SERVICE_ALL_ACCESS_LEN,
		strServiceAllAccess);
	static CHAR strServiceChangeConfig[STRING_RIGHTS_SERVICE_CHANGE_CONFIG_LEN + 1] = ""; // "ServiceChangeConfig"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_CHANGE_CONFIG,
		STRING_RIGHTS_SERVICE_CHANGE_CONFIG_LEN,
		strServiceChangeConfig);
	static CHAR strServiceEnumerateDepedents[STRING_RIGHTS_SERVICE_ENUMERATE_DEPEDENTS_LEN + 1] = ""; // "ServiceEnumerateDepedents"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_ENUMERATE_DEPEDENTS,
		STRING_RIGHTS_SERVICE_ENUMERATE_DEPEDENTS_LEN,
		strServiceEnumerateDepedents);
	static CHAR strServiceInterrogate[STRING_RIGHTS_SERVICE_INTERROGATE_LEN + 1] = ""; // "ServiceInterrogate"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_INTERROGATE,
		STRING_RIGHTS_SERVICE_INTERROGATE_LEN,
		strServiceInterrogate);
	static CHAR strServicePauseContinue[STRING_RIGHTS_SERVICE_PAUSE_CONTINUE_LEN + 1] = ""; // "ServicePauseContinue"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_PAUSE_CONTINUE,
		STRING_RIGHTS_SERVICE_PAUSE_CONTINUE_LEN,
		strServicePauseContinue);
	static CHAR strServiceQueryConfig[STRING_RIGHTS_SERVICE_QUERY_CONFIG_LEN + 1] = ""; // "ServiceQueryConfig"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_QUERY_CONFIG,
		STRING_RIGHTS_SERVICE_QUERY_CONFIG_LEN,
		strServiceQueryConfig);
	static CHAR strServiceQueryStatus[STRING_RIGHTS_SERVICE_QUERY_STATUS_LEN + 1] = ""; // "ServiceQueryStatus"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_QUERY_STATUS,
		STRING_RIGHTS_SERVICE_QUERY_STATUS_LEN,
		strServiceQueryStatus);
	static CHAR strServiceStart[STRING_RIGHTS_SERVICE_START_LEN + 1] = ""; // "ServiceStart"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_START,
		STRING_RIGHTS_SERVICE_START_LEN,
		strServiceStart);
	static CHAR strServiceStop[STRING_RIGHTS_SERVICE_STOP_LEN + 1] = ""; // "ServiceStop"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_STOP,
		STRING_RIGHTS_SERVICE_STOP_LEN,
		strServiceStop);
	static CHAR strServiceUserDefinedControl[STRING_RIGHTS_SERVICE_USER_DEFINED_CONTROL_LEN + 1] = ""; // "ServiceUserDefinedControl"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_SERVICE_USER_DEFINED_CONTROL,
		STRING_RIGHTS_SERVICE_USER_DEFINED_CONTROL_LEN,
		strServiceUserDefinedControl);
	static CHAR strKeyAllAccess[STRING_RIGHTS_KEY_ALL_ACCESS_LEN + 1] = ""; // "KeyAllAccess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_ALL_ACCESS,
		STRING_RIGHTS_KEY_ALL_ACCESS_LEN,
		strKeyAllAccess);
	static CHAR strKeyCreateLink[STRING_RIGHTS_KEY_CREATE_LINK_LEN + 1] = ""; // "KeyCreateLink"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_CREATE_LINK,
		STRING_RIGHTS_KEY_CREATE_LINK_LEN,
		strKeyCreateLink);
	static CHAR strKeyCreateSubKey[STRING_RIGHTS_KEY_CREATE_SUB_KEY_LEN + 1] = ""; // "KeyCreateSubKey"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_CREATE_SUB_KEY,
		STRING_RIGHTS_KEY_CREATE_SUB_KEY_LEN,
		strKeyCreateSubKey);
	static CHAR strKeyEnumerateSubKeys[STRING_RIGHTS_KEY_ENUMERATE_SUB_KEYS_LEN + 1] = ""; // "KeyEnumerateSubKeys"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_ENUMERATE_SUB_KEYS,
		STRING_RIGHTS_KEY_ENUMERATE_SUB_KEYS_LEN,
		strKeyEnumerateSubKeys);
	static CHAR strKeyExecute[STRING_RIGHTS_KEY_EXECUTE_LEN + 1] = ""; // "KeyExecute"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_EXECUTE,
		STRING_RIGHTS_KEY_EXECUTE_LEN,
		strKeyExecute);
	static CHAR strKeyNotify[STRING_RIGHTS_KEY_NOTIFY_LEN + 1] = ""; // "KeyNotify"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_NOTIFY,
		STRING_RIGHTS_KEY_NOTIFY_LEN,
		strKeyNotify);
	static CHAR strKeyQueryValue[STRING_RIGHTS_KEY_QUERY_VALUE_LEN + 1] = ""; // "KeyQueryValue"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_QUERY_VALUE,
		STRING_RIGHTS_KEY_QUERY_VALUE_LEN,
		strKeyQueryValue);
	static CHAR strKeyRead[STRING_RIGHTS_KEY_READ_LEN + 1] = ""; // "KeyRead"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_READ,
		STRING_RIGHTS_KEY_READ_LEN,
		strKeyRead);
	static CHAR strKeySetValue[STRING_RIGHTS_KEY_SET_VALUE_LEN + 1] = ""; // "KeySetValue"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_SET_VALUE,
		STRING_RIGHTS_KEY_SET_VALUE_LEN,
		strKeySetValue);
	static CHAR strKeyWow6432Key[STRING_RIGHTS_KEY_WOW6432_KEY_LEN + 1] = ""; // "KeyWow6432Key"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_WOW6432_KEY,
		STRING_RIGHTS_KEY_WOW6432_KEY_LEN,
		strKeyWow6432Key);
	static CHAR strKeyWow6464Key[STRING_RIGHTS_KEY_WOW6464_KEY_LEN + 1] = ""; // "KeyWow6464Key"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_WOW6464_KEY,
		STRING_RIGHTS_KEY_WOW6464_KEY_LEN,
		strKeyWow6464Key);
	static CHAR strKeyWrite[STRING_RIGHTS_KEY_WRITE_LEN + 1] = ""; // "KeyWrite"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_KEY_WRITE,
		STRING_RIGHTS_KEY_WRITE_LEN,
		strKeyWrite);
	static CHAR strTokenAllAccess[STRING_RIGHTS_TOKEN_ALL_ACCESS_LEN + 1] = ""; // "TokenAllAccess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_ALL_ACCESS,
		STRING_RIGHTS_TOKEN_ALL_ACCESS_LEN,
		strTokenAllAccess);
	static CHAR strTokenAdjustDefault[STRING_RIGHTS_TOKEN_ADJUST_DEFAULT_LEN + 1] = ""; // "TokenAdjustDefault"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_ADJUST_DEFAULT,
		STRING_RIGHTS_TOKEN_ADJUST_DEFAULT_LEN,
		strTokenAdjustDefault);
	static CHAR strTokenAdjustGroups[STRING_RIGHTS_TOKEN_ADJUST_GROUPS_LEN + 1] = ""; // "TokenAdjustGroups"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_ADJUST_GROUPS,
		STRING_RIGHTS_TOKEN_ADJUST_GROUPS_LEN,
		strTokenAdjustGroups);
	static CHAR strTokenAdjustPrivileges[STRING_RIGHTS_TOKEN_ADJUST_PRIVILEGES_LEN + 1] = ""; // "TokenAdjustPrivileges"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_ADJUST_PRIVILEGES,
		STRING_RIGHTS_TOKEN_ADJUST_PRIVILEGES_LEN,
		strTokenAdjustPrivileges);
	static CHAR strTokenAdjustSessionId[STRING_RIGHTS_TOKEN_ADJUST_SESSION_ID_LEN + 1] = ""; // "TokenAdjustSessionId"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_ADJUST_SESSION_ID,
		STRING_RIGHTS_TOKEN_ADJUST_SESSION_ID_LEN,
		strTokenAdjustSessionId);
	static CHAR strTokenAssignPrimary[STRING_RIGHTS_TOKEN_ASSIGN_PRIMARY_LEN + 1] = ""; // "TokenAssignPrimary"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_ASSIGN_PRIMARY,
		STRING_RIGHTS_TOKEN_ASSIGN_PRIMARY_LEN,
		strTokenAssignPrimary);
	static CHAR strTokenDuplicate[STRING_RIGHTS_TOKEN_DUPLICATE_LEN + 1] = ""; // "TokenDuplicate"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_DUPLICATE,
		STRING_RIGHTS_TOKEN_DUPLICATE_LEN,
		strTokenDuplicate);
	static CHAR strTokenExecute[STRING_RIGHTS_TOKEN_EXECUTE_LEN + 1] = ""; // "TokenExecute"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_EXECUTE,
		STRING_RIGHTS_TOKEN_EXECUTE_LEN,
		strTokenExecute);
	static CHAR strTokenImpersonate[STRING_RIGHTS_TOKEN_IMPERSONATE_LEN + 1] = ""; // "TokenImpersonate"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_IMPERSONATE,
		STRING_RIGHTS_TOKEN_IMPERSONATE_LEN,
		strTokenImpersonate);
	static CHAR strTokenQuery[STRING_RIGHTS_TOKEN_QUERY_LEN + 1] = ""; // "TokenQuery"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_QUERY,
		STRING_RIGHTS_TOKEN_QUERY_LEN,
		strTokenQuery);
	static CHAR strTokenQuerySource[STRING_RIGHTS_TOKEN_QUERY_SOURCE_LEN + 1] = ""; // "TokenQuerySource"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_QUERY_SOURCE,
		STRING_RIGHTS_TOKEN_QUERY_SOURCE_LEN,
		strTokenQuerySource);
	static CHAR strTokenRead[STRING_RIGHTS_TOKEN_READ_LEN + 1] = ""; // "TokenRead"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_READ,
		STRING_RIGHTS_TOKEN_READ_LEN,
		strTokenRead);
	static CHAR strTokenWrite[STRING_RIGHTS_TOKEN_WRITE_LEN + 1] = ""; // "TokenWrite"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RIGHTS_TOKEN_WRITE,
		STRING_RIGHTS_TOKEN_WRITE_LEN,
		strTokenWrite);

	// Owner
	PCHAR pOwnerUserName = NULL;
	PCHAR pOwnerDomainName = NULL;
	this->SidToUsernameCustom(
		&(pSecurityInfoCustom->sidOwner),
		(LPVOID *)(&pOwnerUserName),
		(LPVOID *)(&pOwnerDomainName));
	if (pOwnerUserName != NULL && pOwnerDomainName != NULL)
	{
		stringAggregator.AddString(strOWNER);
		stringAggregator.AddString(": ");
		stringAggregator.AddString(pOwnerDomainName);
		stringAggregator.AddString("/");
		stringAggregator.AddString(pOwnerUserName);
		stringAggregator.AddString("\n");
	}

	// Group
	PCHAR pGroupUserName = NULL;
	PCHAR pGroupDomainName = NULL;
	this->SidToUsernameCustom(
		&(pSecurityInfoCustom->sidGroup),
		(LPVOID *)(&pGroupUserName),
		(LPVOID *)(&pGroupDomainName));
	if (pGroupUserName != NULL && pGroupDomainName != NULL)
	{
		stringAggregator.AddString(strGROUP);
		stringAggregator.AddString(": ");
		stringAggregator.AddString(pGroupDomainName);
		stringAggregator.AddString("/");
		stringAggregator.AddString(pGroupUserName);
		stringAggregator.AddString("\n");
	}

	// DACL
	if (pSecurityInfoCustom->acesNum != 0)
	{
		stringAggregator.AddString(strDACL);
		stringAggregator.AddString(":");

		PACE_CUSTOM pAceCustom = NULL;
		PCHAR pAceTrusteeUserName = NULL;
		PCHAR pAceTrusteeDomainName = NULL;

		for (WORD aceIndex = 0; aceIndex < pSecurityInfoCustom->acesNum; ++aceIndex)
		{
			pAceCustom = (PACE_CUSTOM)(&(pSecurityInfoCustom->pAcesCustom[aceIndex]));

			// Trustee name
			this->SidToUsernameCustom(
				&(pAceCustom->sidTrustee),
				(LPVOID *)(&pAceTrusteeUserName),
				(LPVOID *)(&pAceTrusteeDomainName));
			if (pAceTrusteeUserName == NULL || pAceTrusteeDomainName == NULL)
				continue;
			stringAggregator.AddString("\n\t - ");
			stringAggregator.AddString(pAceTrusteeDomainName);
			stringAggregator.AddString("/");
			stringAggregator.AddString(pAceTrusteeUserName);
			stringAggregator.AddString(" ");

			// Allowed/Denied
			stringAggregator.AddString("(");
			stringAggregator.AddString(pAceCustom->allowed ? strALLOWED : strDENIED);
			stringAggregator.AddString("): ");

			// Rights
			if (pAceCustom->accessMask.GenericAll)
			{
				stringAggregator.AddString(strGenericAll);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.GenericRead)
			{
				stringAggregator.AddString(strGenericRead);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.GenericWrite)
			{
				stringAggregator.AddString(strGenericWrite);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.GenericExecute)
			{
				stringAggregator.AddString(strGenericExecute);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.StandardAll)
			{
				stringAggregator.AddString(strStandardAll);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.Delete)
			{
				stringAggregator.AddString(strDelete);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ReadControl)
			{
				stringAggregator.AddString(strReadControl);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.WriteDac)
			{
				stringAggregator.AddString(strWriteDac);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.WriteOwner)
			{
				stringAggregator.AddString(strWriteOwner);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.Synchronize)
			{
				stringAggregator.AddString(strSynchronize);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileReadEA)
			{
				stringAggregator.AddString(strFileReadEA);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileWriteEA)
			{
				stringAggregator.AddString(strFileWriteEA);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileReadAttributes)
			{
				stringAggregator.AddString(strFileReadAttributes);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileWriteAttributes)
			{
				stringAggregator.AddString(strFileWriteAttributes);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileReadData)
			{
				stringAggregator.AddString(strFileReadData);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileWriteData)
			{
				stringAggregator.AddString(strFileWriteData);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileAppendData)
			{
				stringAggregator.AddString(strFileAppendData);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileExecute)
			{
				stringAggregator.AddString(strFileExecute);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileListDirectory)
			{
				stringAggregator.AddString(strFileListDirectory);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileAddFile)
			{
				stringAggregator.AddString(strFileAddFile);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileAddSubdirectory)
			{
				stringAggregator.AddString(strFileAddSubdirectory);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileTraverse)
			{
				stringAggregator.AddString(strFileTraverse);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileDeleteChild)
			{
				stringAggregator.AddString(strFileDeleteChild);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileMapAllAccess)
			{
				stringAggregator.AddString(strFileMapAllAccess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileMapExecute)
			{
				stringAggregator.AddString(strFileMapExecute);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileMapRead)
			{
				stringAggregator.AddString(strFileMapRead);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.FileMapWrite)
			{
				stringAggregator.AddString(strFileMapWrite);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessAllAccess)
			{
				stringAggregator.AddString(strProcessAllAccess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessCreateProcess)
			{
				stringAggregator.AddString(strProcessCreateProcess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessCreateThread)
			{
				stringAggregator.AddString(strProcessCreateThread);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessQueryInformation)
			{
				stringAggregator.AddString(strProcessQueryInformation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessQueryLimitedInformation)
			{
				stringAggregator.AddString(strProcessQueryLimitedInformation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessSetInformation)
			{
				stringAggregator.AddString(strProcessSetInformation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessSetQuota)
			{
				stringAggregator.AddString(strProcessSetQuota);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessSuspendResume)
			{
				stringAggregator.AddString(strProcessSuspendResume);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessTerminate)
			{
				stringAggregator.AddString(strProcessTerminate);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessVmOperation)
			{
				stringAggregator.AddString(strProcessVmOperation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessVmRead)
			{
				stringAggregator.AddString(strProcessVmRead);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ProcessVmWrite)
			{
				stringAggregator.AddString(strProcessVmWrite);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadAllAccess)
			{
				stringAggregator.AddString(strThreadAllAccess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadDirectImpersonation)
			{
				stringAggregator.AddString(strThreadDirectImpersonation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadGetContext)
			{
				stringAggregator.AddString(strThreadGetContext);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadImpersonate)
			{
				stringAggregator.AddString(strThreadImpersonate);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadQueryInformation)
			{
				stringAggregator.AddString(strThreadQueryInformation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadQueryLimitedInformation)
			{
				stringAggregator.AddString(strThreadQueryLimitedInformation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadSetContext)
			{
				stringAggregator.AddString(strThreadSetContext);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadSetInformation)
			{
				stringAggregator.AddString(strThreadSetInformation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadSetLimitedInformation)
			{
				stringAggregator.AddString(strThreadSetLimitedInformation);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadSetThreadToken)
			{
				stringAggregator.AddString(strThreadSetThreadToken);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadSuspendResume)
			{
				stringAggregator.AddString(strThreadSuspendResume);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ThreadTerminate)
			{
				stringAggregator.AddString(strThreadTerminate);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ScManagerAllAccess)
			{
				stringAggregator.AddString(strScManagerAllAccess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ScManagerCreateService)
			{
				stringAggregator.AddString(strScManagerCreateService);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ScManagerConnect)
			{
				stringAggregator.AddString(strScManagerConnect);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ScManagerEnumerateService)
			{
				stringAggregator.AddString(strScManagerEnumerateService);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ScManagerLock)
			{
				stringAggregator.AddString(strScManagerLock);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ScManagerModifyBootConfig)
			{
				stringAggregator.AddString(strScManagerModifyBootConfig);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ScManagerQueryLockStatus)
			{
				stringAggregator.AddString(strScManagerQueryLockStatus);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceAllAccess)
			{
				stringAggregator.AddString(strServiceAllAccess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceChangeConfig)
			{
				stringAggregator.AddString(strServiceChangeConfig);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceEnumerateDepedents)
			{
				stringAggregator.AddString(strServiceEnumerateDepedents);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceInterrogate)
			{
				stringAggregator.AddString(strServiceInterrogate);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServicePauseContinue)
			{
				stringAggregator.AddString(strServicePauseContinue);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceQueryConfig)
			{
				stringAggregator.AddString(strServiceQueryConfig);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceQueryStatus)
			{
				stringAggregator.AddString(strServiceQueryStatus);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceStart)
			{
				stringAggregator.AddString(strServiceStart);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceStop)
			{
				stringAggregator.AddString(strServiceStop);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.ServiceUserDefinedControl)
			{
				stringAggregator.AddString(strServiceUserDefinedControl);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyAllAccess)
			{
				stringAggregator.AddString(strKeyAllAccess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyCreateLink)
			{
				stringAggregator.AddString(strKeyCreateLink);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyCreateSubKey)
			{
				stringAggregator.AddString(strKeyCreateSubKey);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyEnumerateSubKeys)
			{
				stringAggregator.AddString(strKeyEnumerateSubKeys);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyExecute)
			{
				stringAggregator.AddString(strKeyExecute);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyNotify)
			{
				stringAggregator.AddString(strKeyNotify);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyQueryValue)
			{
				stringAggregator.AddString(strKeyQueryValue);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyRead)
			{
				stringAggregator.AddString(strKeyRead);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeySetValue)
			{
				stringAggregator.AddString(strKeySetValue);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyWow6432Key)
			{
				stringAggregator.AddString(strKeyWow6432Key);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyWow6464Key)
			{
				stringAggregator.AddString(strKeyWow6464Key);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.KeyWrite)
			{
				stringAggregator.AddString(strKeyWrite);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenAllAccess)
			{
				stringAggregator.AddString(strTokenAllAccess);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenAdjustDefault)
			{
				stringAggregator.AddString(strTokenAdjustDefault);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenAdjustGroups)
			{
				stringAggregator.AddString(strTokenAdjustGroups);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenAdjustPrivileges)
			{
				stringAggregator.AddString(strTokenAdjustPrivileges);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenAdjustSessionId)
			{
				stringAggregator.AddString(strTokenAdjustSessionId);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenAssignPrimary)
			{
				stringAggregator.AddString(strTokenAssignPrimary);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenDuplicate)
			{
				stringAggregator.AddString(strTokenDuplicate);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenExecute)
			{
				stringAggregator.AddString(strTokenExecute);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenImpersonate)
			{
				stringAggregator.AddString(strTokenImpersonate);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenQuery)
			{
				stringAggregator.AddString(strTokenQuery);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenQuerySource)
			{
				stringAggregator.AddString(strTokenQuerySource);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenRead)
			{
				stringAggregator.AddString(strTokenRead);
				stringAggregator.AddString(commaChar);
			}
			if (pAceCustom->accessMask.TokenWrite)
			{
				stringAggregator.AddString(strTokenWrite);
				stringAggregator.AddString(commaChar);
			}
		}
	}

	DWORD combinedStrLen = stringAggregator.GetTotalLengthOfAllStrings();
	if (combinedStrLen != 0)
	{
		*ppSecurityInfoCustomDescribed = (PCHAR)(this->HeapAllocCustom(combinedStrLen + 1));
		if (*ppSecurityInfoCustomDescribed != NULL)
		{
			stringAggregator.CombineAllStrings(*ppSecurityInfoCustomDescribed);
		}
	}
}
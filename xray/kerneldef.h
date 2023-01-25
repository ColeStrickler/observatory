#pragma once
#include <map>
#include <string>

typedef enum _REG_NOTIFY_CLASS: short
{
	RegNtDeleteKey,
	RegNtPreDeleteKey,
	RegNtSetValueKey,
	RegNtPreSetValueKey,
	RegNtDeleteValueKey,
	RegNtPreDeleteValueKey,
	RegNtSetInformationKey,
	RegNtPreSetInformationKey,
	RegNtRenameKey,
	RegNtPreRenameKey,
	RegNtEnumerateKey,
	RegNtPreEnumerateKey,
	RegNtEnumerateValueKey,
	RegNtPreEnumerateValueKey,
	RegNtQueryKey,
	RegNtPreQueryKey,
	RegNtQueryValueKey,
	RegNtPreQueryValueKey,
	RegNtQueryMultipleValueKey,
	RegNtPreQueryMultipleValueKey,
	RegNtPreCreateKey,
	RegNtPostCreateKey,
	RegNtPreOpenKey,
	RegNtPostOpenKey,
	RegNtKeyHandleClose,
	RegNtPreKeyHandleClose,
	RegNtPostDeleteKey,
	RegNtPostSetValueKey,
	RegNtPostDeleteValueKey,
	RegNtPostSetInformationKey,
	RegNtPostRenameKey,
	RegNtPostEnumerateKey,
	RegNtPostEnumerateValueKey,
	RegNtPostQueryKey,
	RegNtPostQueryValueKey,
	RegNtPostQueryMultipleValueKey,
	RegNtPostKeyHandleClose,
	RegNtPreCreateKeyEx,
	RegNtPostCreateKeyEx,
	RegNtPreOpenKeyEx,
	RegNtPostOpenKeyEx,
	RegNtPreFlushKey,
	RegNtPostFlushKey,
	RegNtPreLoadKey,
	RegNtPostLoadKey,
	RegNtPreUnLoadKey,
	RegNtPostUnLoadKey,
	RegNtPreQueryKeySecurity,
	RegNtPostQueryKeySecurity,
	RegNtPreSetKeySecurity,
	RegNtPostSetKeySecurity,
	RegNtCallbackObjectContextCleanup,
	RegNtPreRestoreKey,
	RegNtPostRestoreKey,
	RegNtPreSaveKey,
	RegNtPostSaveKey,
	RegNtPreReplaceKey,
	RegNtPostReplaceKey,
	RegNtPreQueryKeyName,
	RegNtPostQueryKeyName,
	RegNtPreSaveMergedKey,
	RegNtPostSaveMergedKey,
	MaxRegNtNotifyClass
} REG_NOTIFY_CLASS;




static const char* REG_NOTIFY_CLASS_MAPPINGS[] =
{
	"RegNtDeleteKey",
	"RegNtPreDeleteKey",
	"RegNtSetValueKey",
	"RegNtPreSetValueKey",
	"RegNtDeleteValueKey",
	"RegNtPreDeleteValueKey",
	"RegNtSetInformationKey",
	"RegNtPreSetInformationKey",
	"RegNtRenameKey",
	"RegNtPreRenameKey",
	"RegNtEnumerateKey",
	"RegNtPreEnumerateKey",
	"RegNtEnumerateValueKey",
	"RegNtPreEnumerateValueKey",
	"RegNtQueryKey",
	"RegNtPreQueryKey",
	"RegNtQueryValueKey",
	"RegNtPreQueryValueKey",
	"RegNtQueryMultipleValueKey",
	"RegNtPreQueryMultipleValueKey",
	"RegNtPreCreateKey",
	"RegNtPostCreateKey",
	"RegNtPreOpenKeyv",
	"RegNtPostOpenKey",
	"RegNtKeyHandleClose",
	"RegNtPreKeyHandleClose",
	"RegNtPostDeleteKey",
	"RegNtPostSetValueKey",
	"RegNtPostDeleteValueKey",
	"RegNtPostSetInformationKey",
	"RegNtPostRenameKey",
	"RegNtPostEnumerateKey",
	"RegNtPostEnumerateValueKey",
	"RegNtPostQueryKey",
	"RegNtPostQueryValueKey",
	"RegNtPostQueryMultipleValueKey",
	"RegNtPostKeyHandleClose",
	"RegNtPreCreateKeyEx",
	"RegNtPostCreateKeyEx",
	"RegNtPreOpenKeyEx",
	"RegNtPostOpenKeyEx",
	"RegNtPreFlushKey",
	"RegNtPostFlushKey",
	"RegNtPreLoadKey",
	"RegNtPostLoadKey",
	"RegNtPreUnLoadKey",
	"RegNtPostUnLoadKey",
	"RegNtPreQueryKeySecurity",
	"RegNtPostQueryKeySecurity",
	"RegNtPreSetKeySecurity",
	"RegNtPostSetKeySecurity",
	"RegNtCallbackObjectContextCleanup",
	"RegNtPreRestoreKey",
	"RegNtPostRestoreKey",
	"RegNtPreSaveKey",
	"RegNtPostSaveKey",
	"RegNtPreReplaceKey",
	"RegNtPostReplaceKey",
	"RegNtPreQueryKeyName",
	"RegNtPostQueryKeyName",
	"RegNtPreSaveMergedKey",
	"RegNtPostSaveMergedKey",
	"MaxRegNtNotifyClass"
};
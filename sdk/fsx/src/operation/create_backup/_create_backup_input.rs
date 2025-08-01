// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request object for the <code>CreateBackup</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBackupInput {
    /// <p>The ID of the file system to back up.</p>
    pub file_system_id: ::std::option::Option<::std::string::String>,
    /// <p>(Optional) A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent creation. This string is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>(Optional) The tags to apply to the backup at backup creation. The key value of the <code>Name</code> tag appears in the console as the backup name. If you have set <code>CopyTagsToBackups</code> to <code>true</code>, and you specify one or more tags using the <code>CreateBackup</code> operation, no existing file system tags are copied from the file system to the backup.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>(Optional) The ID of the FSx for ONTAP volume to back up.</p>
    pub volume_id: ::std::option::Option<::std::string::String>,
}
impl CreateBackupInput {
    /// <p>The ID of the file system to back up.</p>
    pub fn file_system_id(&self) -> ::std::option::Option<&str> {
        self.file_system_id.as_deref()
    }
    /// <p>(Optional) A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent creation. This string is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>(Optional) The tags to apply to the backup at backup creation. The key value of the <code>Name</code> tag appears in the console as the backup name. If you have set <code>CopyTagsToBackups</code> to <code>true</code>, and you specify one or more tags using the <code>CreateBackup</code> operation, no existing file system tags are copied from the file system to the backup.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>(Optional) The ID of the FSx for ONTAP volume to back up.</p>
    pub fn volume_id(&self) -> ::std::option::Option<&str> {
        self.volume_id.as_deref()
    }
}
impl CreateBackupInput {
    /// Creates a new builder-style object to manufacture [`CreateBackupInput`](crate::operation::create_backup::CreateBackupInput).
    pub fn builder() -> crate::operation::create_backup::builders::CreateBackupInputBuilder {
        crate::operation::create_backup::builders::CreateBackupInputBuilder::default()
    }
}

/// A builder for [`CreateBackupInput`](crate::operation::create_backup::CreateBackupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBackupInputBuilder {
    pub(crate) file_system_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) volume_id: ::std::option::Option<::std::string::String>,
}
impl CreateBackupInputBuilder {
    /// <p>The ID of the file system to back up.</p>
    pub fn file_system_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the file system to back up.</p>
    pub fn set_file_system_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_id = input;
        self
    }
    /// <p>The ID of the file system to back up.</p>
    pub fn get_file_system_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_id
    }
    /// <p>(Optional) A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent creation. This string is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent creation. This string is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>(Optional) A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent creation. This string is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>(Optional) The tags to apply to the backup at backup creation. The key value of the <code>Name</code> tag appears in the console as the backup name. If you have set <code>CopyTagsToBackups</code> to <code>true</code>, and you specify one or more tags using the <code>CreateBackup</code> operation, no existing file system tags are copied from the file system to the backup.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>(Optional) The tags to apply to the backup at backup creation. The key value of the <code>Name</code> tag appears in the console as the backup name. If you have set <code>CopyTagsToBackups</code> to <code>true</code>, and you specify one or more tags using the <code>CreateBackup</code> operation, no existing file system tags are copied from the file system to the backup.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>(Optional) The tags to apply to the backup at backup creation. The key value of the <code>Name</code> tag appears in the console as the backup name. If you have set <code>CopyTagsToBackups</code> to <code>true</code>, and you specify one or more tags using the <code>CreateBackup</code> operation, no existing file system tags are copied from the file system to the backup.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>(Optional) The ID of the FSx for ONTAP volume to back up.</p>
    pub fn volume_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) The ID of the FSx for ONTAP volume to back up.</p>
    pub fn set_volume_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_id = input;
        self
    }
    /// <p>(Optional) The ID of the FSx for ONTAP volume to back up.</p>
    pub fn get_volume_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_id
    }
    /// Consumes the builder and constructs a [`CreateBackupInput`](crate::operation::create_backup::CreateBackupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_backup::CreateBackupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_backup::CreateBackupInput {
            file_system_id: self.file_system_id,
            client_request_token: self.client_request_token,
            tags: self.tags,
            volume_id: self.volume_id,
        })
    }
}

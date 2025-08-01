// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response object for the <code>CreateBackup</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBackupOutput {
    /// <p>A description of the backup.</p>
    pub backup: ::std::option::Option<crate::types::Backup>,
    _request_id: Option<String>,
}
impl CreateBackupOutput {
    /// <p>A description of the backup.</p>
    pub fn backup(&self) -> ::std::option::Option<&crate::types::Backup> {
        self.backup.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateBackupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateBackupOutput {
    /// Creates a new builder-style object to manufacture [`CreateBackupOutput`](crate::operation::create_backup::CreateBackupOutput).
    pub fn builder() -> crate::operation::create_backup::builders::CreateBackupOutputBuilder {
        crate::operation::create_backup::builders::CreateBackupOutputBuilder::default()
    }
}

/// A builder for [`CreateBackupOutput`](crate::operation::create_backup::CreateBackupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBackupOutputBuilder {
    pub(crate) backup: ::std::option::Option<crate::types::Backup>,
    _request_id: Option<String>,
}
impl CreateBackupOutputBuilder {
    /// <p>A description of the backup.</p>
    pub fn backup(mut self, input: crate::types::Backup) -> Self {
        self.backup = ::std::option::Option::Some(input);
        self
    }
    /// <p>A description of the backup.</p>
    pub fn set_backup(mut self, input: ::std::option::Option<crate::types::Backup>) -> Self {
        self.backup = input;
        self
    }
    /// <p>A description of the backup.</p>
    pub fn get_backup(&self) -> &::std::option::Option<crate::types::Backup> {
        &self.backup
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateBackupOutput`](crate::operation::create_backup::CreateBackupOutput).
    pub fn build(self) -> crate::operation::create_backup::CreateBackupOutput {
        crate::operation::create_backup::CreateBackupOutput {
            backup: self.backup,
            _request_id: self._request_id,
        }
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBackupSelectionOutput {
    /// <p>Specifies the body of a request to assign a set of resources to a backup plan.</p>
    pub backup_selection: ::std::option::Option<crate::types::BackupSelection>,
    /// <p>Uniquely identifies the body of a request to assign a set of resources to a backup plan.</p>
    pub selection_id: ::std::option::Option<::std::string::String>,
    /// <p>Uniquely identifies a backup plan.</p>
    pub backup_plan_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time a backup selection is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice.</p>
    pub creator_request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetBackupSelectionOutput {
    /// <p>Specifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn backup_selection(&self) -> ::std::option::Option<&crate::types::BackupSelection> {
        self.backup_selection.as_ref()
    }
    /// <p>Uniquely identifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn selection_id(&self) -> ::std::option::Option<&str> {
        self.selection_id.as_deref()
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn backup_plan_id(&self) -> ::std::option::Option<&str> {
        self.backup_plan_id.as_deref()
    }
    /// <p>The date and time a backup selection is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice.</p>
    pub fn creator_request_id(&self) -> ::std::option::Option<&str> {
        self.creator_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetBackupSelectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBackupSelectionOutput {
    /// Creates a new builder-style object to manufacture [`GetBackupSelectionOutput`](crate::operation::get_backup_selection::GetBackupSelectionOutput).
    pub fn builder() -> crate::operation::get_backup_selection::builders::GetBackupSelectionOutputBuilder {
        crate::operation::get_backup_selection::builders::GetBackupSelectionOutputBuilder::default()
    }
}

/// A builder for [`GetBackupSelectionOutput`](crate::operation::get_backup_selection::GetBackupSelectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBackupSelectionOutputBuilder {
    pub(crate) backup_selection: ::std::option::Option<crate::types::BackupSelection>,
    pub(crate) selection_id: ::std::option::Option<::std::string::String>,
    pub(crate) backup_plan_id: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creator_request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetBackupSelectionOutputBuilder {
    /// <p>Specifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn backup_selection(mut self, input: crate::types::BackupSelection) -> Self {
        self.backup_selection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn set_backup_selection(mut self, input: ::std::option::Option<crate::types::BackupSelection>) -> Self {
        self.backup_selection = input;
        self
    }
    /// <p>Specifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn get_backup_selection(&self) -> &::std::option::Option<crate::types::BackupSelection> {
        &self.backup_selection
    }
    /// <p>Uniquely identifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn selection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.selection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Uniquely identifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn set_selection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.selection_id = input;
        self
    }
    /// <p>Uniquely identifies the body of a request to assign a set of resources to a backup plan.</p>
    pub fn get_selection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.selection_id
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn backup_plan_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_plan_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn set_backup_plan_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_plan_id = input;
        self
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn get_backup_plan_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_plan_id
    }
    /// <p>The date and time a backup selection is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a backup selection is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date and time a backup selection is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice.</p>
    pub fn creator_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creator_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice.</p>
    pub fn set_creator_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creator_request_id = input;
        self
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice.</p>
    pub fn get_creator_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.creator_request_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetBackupSelectionOutput`](crate::operation::get_backup_selection::GetBackupSelectionOutput).
    pub fn build(self) -> crate::operation::get_backup_selection::GetBackupSelectionOutput {
        crate::operation::get_backup_selection::GetBackupSelectionOutput {
            backup_selection: self.backup_selection,
            selection_id: self.selection_id,
            backup_plan_id: self.backup_plan_id,
            creation_date: self.creation_date,
            creator_request_id: self.creator_request_id,
            _request_id: self._request_id,
        }
    }
}

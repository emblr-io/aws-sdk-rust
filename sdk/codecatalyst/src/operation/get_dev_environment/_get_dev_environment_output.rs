// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDevEnvironmentOutput {
    /// <p>The name of the space.</p>
    pub space_name: ::std::string::String,
    /// <p>The name of the project in the space.</p>
    pub project_name: ::std::string::String,
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub id: ::std::string::String,
    /// <p>The time when the Dev Environment was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub last_updated_time: ::aws_smithy_types::DateTime,
    /// <p>The system-generated unique ID of the user who created the Dev Environment.</p>
    pub creator_id: ::std::string::String,
    /// <p>The current status of the Dev Environment.</p>
    pub status: crate::types::DevEnvironmentStatus,
    /// <p>The reason for the status.</p>
    pub status_reason: ::std::option::Option<::std::string::String>,
    /// <p>The source repository that contains the branch cloned into the Dev Environment.</p>
    pub repositories: ::std::vec::Vec<crate::types::DevEnvironmentRepositorySummary>,
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub alias: ::std::option::Option<::std::string::String>,
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub ides: ::std::option::Option<::std::vec::Vec<crate::types::Ide>>,
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub instance_type: crate::types::InstanceType,
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub inactivity_timeout_minutes: i32,
    /// <p>Information about the amount of storage allocated to the Dev Environment. By default, a Dev Environment is configured to have 16GB of persistent storage.</p>
    pub persistent_storage: ::std::option::Option<crate::types::PersistentStorage>,
    /// <p>The name of the connection used to connect to Amazon VPC used when the Dev Environment was created, if any.</p>
    pub vpc_connection_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDevEnvironmentOutput {
    /// <p>The name of the space.</p>
    pub fn space_name(&self) -> &str {
        use std::ops::Deref;
        self.space_name.deref()
    }
    /// <p>The name of the project in the space.</p>
    pub fn project_name(&self) -> &str {
        use std::ops::Deref;
        self.project_name.deref()
    }
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The time when the Dev Environment was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub fn last_updated_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_updated_time
    }
    /// <p>The system-generated unique ID of the user who created the Dev Environment.</p>
    pub fn creator_id(&self) -> &str {
        use std::ops::Deref;
        self.creator_id.deref()
    }
    /// <p>The current status of the Dev Environment.</p>
    pub fn status(&self) -> &crate::types::DevEnvironmentStatus {
        &self.status
    }
    /// <p>The reason for the status.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&str> {
        self.status_reason.as_deref()
    }
    /// <p>The source repository that contains the branch cloned into the Dev Environment.</p>
    pub fn repositories(&self) -> &[crate::types::DevEnvironmentRepositorySummary] {
        use std::ops::Deref;
        self.repositories.deref()
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ides.is_none()`.
    pub fn ides(&self) -> &[crate::types::Ide] {
        self.ides.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub fn instance_type(&self) -> &crate::types::InstanceType {
        &self.instance_type
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub fn inactivity_timeout_minutes(&self) -> i32 {
        self.inactivity_timeout_minutes
    }
    /// <p>Information about the amount of storage allocated to the Dev Environment. By default, a Dev Environment is configured to have 16GB of persistent storage.</p>
    pub fn persistent_storage(&self) -> ::std::option::Option<&crate::types::PersistentStorage> {
        self.persistent_storage.as_ref()
    }
    /// <p>The name of the connection used to connect to Amazon VPC used when the Dev Environment was created, if any.</p>
    pub fn vpc_connection_name(&self) -> ::std::option::Option<&str> {
        self.vpc_connection_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetDevEnvironmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDevEnvironmentOutput {
    /// Creates a new builder-style object to manufacture [`GetDevEnvironmentOutput`](crate::operation::get_dev_environment::GetDevEnvironmentOutput).
    pub fn builder() -> crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder {
        crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::default()
    }
}

/// A builder for [`GetDevEnvironmentOutput`](crate::operation::get_dev_environment::GetDevEnvironmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDevEnvironmentOutputBuilder {
    pub(crate) space_name: ::std::option::Option<::std::string::String>,
    pub(crate) project_name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creator_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DevEnvironmentStatus>,
    pub(crate) status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) repositories: ::std::option::Option<::std::vec::Vec<crate::types::DevEnvironmentRepositorySummary>>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
    pub(crate) ides: ::std::option::Option<::std::vec::Vec<crate::types::Ide>>,
    pub(crate) instance_type: ::std::option::Option<crate::types::InstanceType>,
    pub(crate) inactivity_timeout_minutes: ::std::option::Option<i32>,
    pub(crate) persistent_storage: ::std::option::Option<crate::types::PersistentStorage>,
    pub(crate) vpc_connection_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDevEnvironmentOutputBuilder {
    /// <p>The name of the space.</p>
    /// This field is required.
    pub fn space_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.space_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the space.</p>
    pub fn set_space_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.space_name = input;
        self
    }
    /// <p>The name of the space.</p>
    pub fn get_space_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.space_name
    }
    /// <p>The name of the project in the space.</p>
    /// This field is required.
    pub fn project_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn set_project_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_name = input;
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn get_project_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_name
    }
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The system-generated unique ID of the Dev Environment.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The time when the Dev Environment was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    /// This field is required.
    pub fn last_updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the Dev Environment was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>The time when the Dev Environment was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time
    }
    /// <p>The system-generated unique ID of the user who created the Dev Environment.</p>
    /// This field is required.
    pub fn creator_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creator_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated unique ID of the user who created the Dev Environment.</p>
    pub fn set_creator_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creator_id = input;
        self
    }
    /// <p>The system-generated unique ID of the user who created the Dev Environment.</p>
    pub fn get_creator_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.creator_id
    }
    /// <p>The current status of the Dev Environment.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::DevEnvironmentStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the Dev Environment.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DevEnvironmentStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the Dev Environment.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DevEnvironmentStatus> {
        &self.status
    }
    /// <p>The reason for the status.</p>
    pub fn status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason for the status.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The reason for the status.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_reason
    }
    /// Appends an item to `repositories`.
    ///
    /// To override the contents of this collection use [`set_repositories`](Self::set_repositories).
    ///
    /// <p>The source repository that contains the branch cloned into the Dev Environment.</p>
    pub fn repositories(mut self, input: crate::types::DevEnvironmentRepositorySummary) -> Self {
        let mut v = self.repositories.unwrap_or_default();
        v.push(input);
        self.repositories = ::std::option::Option::Some(v);
        self
    }
    /// <p>The source repository that contains the branch cloned into the Dev Environment.</p>
    pub fn set_repositories(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DevEnvironmentRepositorySummary>>) -> Self {
        self.repositories = input;
        self
    }
    /// <p>The source repository that contains the branch cloned into the Dev Environment.</p>
    pub fn get_repositories(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DevEnvironmentRepositorySummary>> {
        &self.repositories
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn set_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias = input;
        self
    }
    /// <p>The user-specified alias for the Dev Environment.</p>
    pub fn get_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias
    }
    /// Appends an item to `ides`.
    ///
    /// To override the contents of this collection use [`set_ides`](Self::set_ides).
    ///
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub fn ides(mut self, input: crate::types::Ide) -> Self {
        let mut v = self.ides.unwrap_or_default();
        v.push(input);
        self.ides = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub fn set_ides(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Ide>>) -> Self {
        self.ides = input;
        self
    }
    /// <p>Information about the integrated development environment (IDE) configured for the Dev Environment.</p>
    pub fn get_ides(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Ide>> {
        &self.ides
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    /// This field is required.
    pub fn instance_type(mut self, input: crate::types::InstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::InstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The Amazon EC2 instace type to use for the Dev Environment.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::InstanceType> {
        &self.instance_type
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    /// This field is required.
    pub fn inactivity_timeout_minutes(mut self, input: i32) -> Self {
        self.inactivity_timeout_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub fn set_inactivity_timeout_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inactivity_timeout_minutes = input;
        self
    }
    /// <p>The amount of time the Dev Environment will run without any activity detected before stopping, in minutes.</p>
    pub fn get_inactivity_timeout_minutes(&self) -> &::std::option::Option<i32> {
        &self.inactivity_timeout_minutes
    }
    /// <p>Information about the amount of storage allocated to the Dev Environment. By default, a Dev Environment is configured to have 16GB of persistent storage.</p>
    /// This field is required.
    pub fn persistent_storage(mut self, input: crate::types::PersistentStorage) -> Self {
        self.persistent_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the amount of storage allocated to the Dev Environment. By default, a Dev Environment is configured to have 16GB of persistent storage.</p>
    pub fn set_persistent_storage(mut self, input: ::std::option::Option<crate::types::PersistentStorage>) -> Self {
        self.persistent_storage = input;
        self
    }
    /// <p>Information about the amount of storage allocated to the Dev Environment. By default, a Dev Environment is configured to have 16GB of persistent storage.</p>
    pub fn get_persistent_storage(&self) -> &::std::option::Option<crate::types::PersistentStorage> {
        &self.persistent_storage
    }
    /// <p>The name of the connection used to connect to Amazon VPC used when the Dev Environment was created, if any.</p>
    pub fn vpc_connection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_connection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the connection used to connect to Amazon VPC used when the Dev Environment was created, if any.</p>
    pub fn set_vpc_connection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_connection_name = input;
        self
    }
    /// <p>The name of the connection used to connect to Amazon VPC used when the Dev Environment was created, if any.</p>
    pub fn get_vpc_connection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_connection_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDevEnvironmentOutput`](crate::operation::get_dev_environment::GetDevEnvironmentOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`space_name`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::space_name)
    /// - [`project_name`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::project_name)
    /// - [`id`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::id)
    /// - [`last_updated_time`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::last_updated_time)
    /// - [`creator_id`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::creator_id)
    /// - [`status`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::status)
    /// - [`repositories`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::repositories)
    /// - [`instance_type`](crate::operation::get_dev_environment::builders::GetDevEnvironmentOutputBuilder::instance_type)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_dev_environment::GetDevEnvironmentOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_dev_environment::GetDevEnvironmentOutput {
            space_name: self.space_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "space_name",
                    "space_name was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            project_name: self.project_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "project_name",
                    "project_name was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            last_updated_time: self.last_updated_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_updated_time",
                    "last_updated_time was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            creator_id: self.creator_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creator_id",
                    "creator_id was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            status_reason: self.status_reason,
            repositories: self.repositories.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "repositories",
                    "repositories was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            alias: self.alias,
            ides: self.ides,
            instance_type: self.instance_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "instance_type",
                    "instance_type was not specified but it is required when building GetDevEnvironmentOutput",
                )
            })?,
            inactivity_timeout_minutes: self.inactivity_timeout_minutes.unwrap_or_default(),
            persistent_storage: self.persistent_storage,
            vpc_connection_name: self.vpc_connection_name,
            _request_id: self._request_id,
        })
    }
}

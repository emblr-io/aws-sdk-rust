// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMonitorOutput {
    /// <p>The Amazon Resource Name (ARN) of the monitor.</p>
    pub monitor_arn: ::std::string::String,
    /// <p>The name of the monitor.</p>
    pub monitor_name: ::std::string::String,
    /// <p>The status of a monitor. The status can be one of the following</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The monitor is in the process of being created.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The monitor is active.</p></li>
    /// <li>
    /// <p><code>INACTIVE</code>: The monitor is inactive.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: Monitor creation failed due to an error.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The monitor is in the process of being deleted.</p></li>
    /// </ul>
    pub monitor_status: crate::types::MonitorStatus,
    /// <p>The local resources to monitor. A local resource, in a bi-directional flow of a workload, is the host where the agent is installed.</p>
    pub local_resources: ::std::vec::Vec<crate::types::MonitorLocalResource>,
    /// <p>The remote resources to monitor. A remote resource is the other endpoint in the bi-directional flow of a workload, with a local resource. For example, Amazon Relational Database Service (RDS) can be a remote resource. The remote resource is identified by its ARN or an identifier.</p>
    pub remote_resources: ::std::vec::Vec<crate::types::MonitorRemoteResource>,
    /// <p>The date and time when the monitor was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The last date and time that the monitor was modified.</p>
    pub modified_at: ::aws_smithy_types::DateTime,
    /// <p>The tags for a monitor.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateMonitorOutput {
    /// <p>The Amazon Resource Name (ARN) of the monitor.</p>
    pub fn monitor_arn(&self) -> &str {
        use std::ops::Deref;
        self.monitor_arn.deref()
    }
    /// <p>The name of the monitor.</p>
    pub fn monitor_name(&self) -> &str {
        use std::ops::Deref;
        self.monitor_name.deref()
    }
    /// <p>The status of a monitor. The status can be one of the following</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The monitor is in the process of being created.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The monitor is active.</p></li>
    /// <li>
    /// <p><code>INACTIVE</code>: The monitor is inactive.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: Monitor creation failed due to an error.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The monitor is in the process of being deleted.</p></li>
    /// </ul>
    pub fn monitor_status(&self) -> &crate::types::MonitorStatus {
        &self.monitor_status
    }
    /// <p>The local resources to monitor. A local resource, in a bi-directional flow of a workload, is the host where the agent is installed.</p>
    pub fn local_resources(&self) -> &[crate::types::MonitorLocalResource] {
        use std::ops::Deref;
        self.local_resources.deref()
    }
    /// <p>The remote resources to monitor. A remote resource is the other endpoint in the bi-directional flow of a workload, with a local resource. For example, Amazon Relational Database Service (RDS) can be a remote resource. The remote resource is identified by its ARN or an identifier.</p>
    pub fn remote_resources(&self) -> &[crate::types::MonitorRemoteResource] {
        use std::ops::Deref;
        self.remote_resources.deref()
    }
    /// <p>The date and time when the monitor was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The last date and time that the monitor was modified.</p>
    pub fn modified_at(&self) -> &::aws_smithy_types::DateTime {
        &self.modified_at
    }
    /// <p>The tags for a monitor.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateMonitorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateMonitorOutput {
    /// Creates a new builder-style object to manufacture [`CreateMonitorOutput`](crate::operation::create_monitor::CreateMonitorOutput).
    pub fn builder() -> crate::operation::create_monitor::builders::CreateMonitorOutputBuilder {
        crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::default()
    }
}

/// A builder for [`CreateMonitorOutput`](crate::operation::create_monitor::CreateMonitorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMonitorOutputBuilder {
    pub(crate) monitor_arn: ::std::option::Option<::std::string::String>,
    pub(crate) monitor_name: ::std::option::Option<::std::string::String>,
    pub(crate) monitor_status: ::std::option::Option<crate::types::MonitorStatus>,
    pub(crate) local_resources: ::std::option::Option<::std::vec::Vec<crate::types::MonitorLocalResource>>,
    pub(crate) remote_resources: ::std::option::Option<::std::vec::Vec<crate::types::MonitorRemoteResource>>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateMonitorOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the monitor.</p>
    /// This field is required.
    pub fn monitor_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitor_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the monitor.</p>
    pub fn set_monitor_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitor_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the monitor.</p>
    pub fn get_monitor_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitor_arn
    }
    /// <p>The name of the monitor.</p>
    /// This field is required.
    pub fn monitor_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitor_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the monitor.</p>
    pub fn set_monitor_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitor_name = input;
        self
    }
    /// <p>The name of the monitor.</p>
    pub fn get_monitor_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitor_name
    }
    /// <p>The status of a monitor. The status can be one of the following</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The monitor is in the process of being created.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The monitor is active.</p></li>
    /// <li>
    /// <p><code>INACTIVE</code>: The monitor is inactive.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: Monitor creation failed due to an error.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The monitor is in the process of being deleted.</p></li>
    /// </ul>
    /// This field is required.
    pub fn monitor_status(mut self, input: crate::types::MonitorStatus) -> Self {
        self.monitor_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a monitor. The status can be one of the following</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The monitor is in the process of being created.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The monitor is active.</p></li>
    /// <li>
    /// <p><code>INACTIVE</code>: The monitor is inactive.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: Monitor creation failed due to an error.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The monitor is in the process of being deleted.</p></li>
    /// </ul>
    pub fn set_monitor_status(mut self, input: ::std::option::Option<crate::types::MonitorStatus>) -> Self {
        self.monitor_status = input;
        self
    }
    /// <p>The status of a monitor. The status can be one of the following</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The monitor is in the process of being created.</p></li>
    /// <li>
    /// <p><code>ACTIVE</code>: The monitor is active.</p></li>
    /// <li>
    /// <p><code>INACTIVE</code>: The monitor is inactive.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: Monitor creation failed due to an error.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: The monitor is in the process of being deleted.</p></li>
    /// </ul>
    pub fn get_monitor_status(&self) -> &::std::option::Option<crate::types::MonitorStatus> {
        &self.monitor_status
    }
    /// Appends an item to `local_resources`.
    ///
    /// To override the contents of this collection use [`set_local_resources`](Self::set_local_resources).
    ///
    /// <p>The local resources to monitor. A local resource, in a bi-directional flow of a workload, is the host where the agent is installed.</p>
    pub fn local_resources(mut self, input: crate::types::MonitorLocalResource) -> Self {
        let mut v = self.local_resources.unwrap_or_default();
        v.push(input);
        self.local_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The local resources to monitor. A local resource, in a bi-directional flow of a workload, is the host where the agent is installed.</p>
    pub fn set_local_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MonitorLocalResource>>) -> Self {
        self.local_resources = input;
        self
    }
    /// <p>The local resources to monitor. A local resource, in a bi-directional flow of a workload, is the host where the agent is installed.</p>
    pub fn get_local_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MonitorLocalResource>> {
        &self.local_resources
    }
    /// Appends an item to `remote_resources`.
    ///
    /// To override the contents of this collection use [`set_remote_resources`](Self::set_remote_resources).
    ///
    /// <p>The remote resources to monitor. A remote resource is the other endpoint in the bi-directional flow of a workload, with a local resource. For example, Amazon Relational Database Service (RDS) can be a remote resource. The remote resource is identified by its ARN or an identifier.</p>
    pub fn remote_resources(mut self, input: crate::types::MonitorRemoteResource) -> Self {
        let mut v = self.remote_resources.unwrap_or_default();
        v.push(input);
        self.remote_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The remote resources to monitor. A remote resource is the other endpoint in the bi-directional flow of a workload, with a local resource. For example, Amazon Relational Database Service (RDS) can be a remote resource. The remote resource is identified by its ARN or an identifier.</p>
    pub fn set_remote_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MonitorRemoteResource>>) -> Self {
        self.remote_resources = input;
        self
    }
    /// <p>The remote resources to monitor. A remote resource is the other endpoint in the bi-directional flow of a workload, with a local resource. For example, Amazon Relational Database Service (RDS) can be a remote resource. The remote resource is identified by its ARN or an identifier.</p>
    pub fn get_remote_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MonitorRemoteResource>> {
        &self.remote_resources
    }
    /// <p>The date and time when the monitor was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the monitor was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time when the monitor was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The last date and time that the monitor was modified.</p>
    /// This field is required.
    pub fn modified_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last date and time that the monitor was modified.</p>
    pub fn set_modified_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_at = input;
        self
    }
    /// <p>The last date and time that the monitor was modified.</p>
    pub fn get_modified_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_at
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for a monitor.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags for a monitor.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for a monitor.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateMonitorOutput`](crate::operation::create_monitor::CreateMonitorOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`monitor_arn`](crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::monitor_arn)
    /// - [`monitor_name`](crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::monitor_name)
    /// - [`monitor_status`](crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::monitor_status)
    /// - [`local_resources`](crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::local_resources)
    /// - [`remote_resources`](crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::remote_resources)
    /// - [`created_at`](crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::created_at)
    /// - [`modified_at`](crate::operation::create_monitor::builders::CreateMonitorOutputBuilder::modified_at)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_monitor::CreateMonitorOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_monitor::CreateMonitorOutput {
            monitor_arn: self.monitor_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "monitor_arn",
                    "monitor_arn was not specified but it is required when building CreateMonitorOutput",
                )
            })?,
            monitor_name: self.monitor_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "monitor_name",
                    "monitor_name was not specified but it is required when building CreateMonitorOutput",
                )
            })?,
            monitor_status: self.monitor_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "monitor_status",
                    "monitor_status was not specified but it is required when building CreateMonitorOutput",
                )
            })?,
            local_resources: self.local_resources.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "local_resources",
                    "local_resources was not specified but it is required when building CreateMonitorOutput",
                )
            })?,
            remote_resources: self.remote_resources.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "remote_resources",
                    "remote_resources was not specified but it is required when building CreateMonitorOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building CreateMonitorOutput",
                )
            })?,
            modified_at: self.modified_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "modified_at",
                    "modified_at was not specified but it is required when building CreateMonitorOutput",
                )
            })?,
            tags: self.tags,
            _request_id: self._request_id,
        })
    }
}

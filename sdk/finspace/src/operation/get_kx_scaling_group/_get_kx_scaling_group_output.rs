// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetKxScalingGroupOutput {
    /// <p>A unique identifier for the kdb scaling group.</p>
    pub scaling_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN identifier for the scaling group.</p>
    pub scaling_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The memory and CPU capabilities of the scaling group host on which FinSpace Managed kdb clusters will be placed.</p>
    /// <p>It can have one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>kx.sg.large</code> – The host type with a configuration of 16 GiB memory and 2 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.xlarge</code> – The host type with a configuration of 32 GiB memory and 4 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.2xlarge</code> – The host type with a configuration of 64 GiB memory and 8 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.4xlarge</code> – The host type with a configuration of 108 GiB memory and 16 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.8xlarge</code> – The host type with a configuration of 216 GiB memory and 32 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.16xlarge</code> – The host type with a configuration of 432 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.32xlarge</code> – The host type with a configuration of 864 GiB memory and 128 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.16xlarge</code> – The host type with a configuration of 1949 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.24xlarge</code> – The host type with a configuration of 2948 GiB memory and 96 vCPUs.</p></li>
    /// </ul>
    pub host_type: ::std::option::Option<::std::string::String>,
    /// <p>The list of Managed kdb clusters that are currently active in the given scaling group.</p>
    pub clusters: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The identifier of the availability zones.</p>
    pub availability_zone_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of scaling group.</p>
    /// <ul>
    /// <li>
    /// <p>CREATING – The scaling group creation is in progress.</p></li>
    /// <li>
    /// <p>CREATE_FAILED – The scaling group creation has failed.</p></li>
    /// <li>
    /// <p>ACTIVE – The scaling group is active.</p></li>
    /// <li>
    /// <p>UPDATING – The scaling group is in the process of being updated.</p></li>
    /// <li>
    /// <p>UPDATE_FAILED – The update action failed.</p></li>
    /// <li>
    /// <p>DELETING – The scaling group is in the process of being deleted.</p></li>
    /// <li>
    /// <p>DELETE_FAILED – The system failed to delete the scaling group.</p></li>
    /// <li>
    /// <p>DELETED – The scaling group is successfully deleted.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::KxScalingGroupStatus>,
    /// <p>The error message when a failed state occurs.</p>
    pub status_reason: ::std::option::Option<::std::string::String>,
    /// <p>The last time that the scaling group was updated in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub last_modified_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp at which the scaling group was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetKxScalingGroupOutput {
    /// <p>A unique identifier for the kdb scaling group.</p>
    pub fn scaling_group_name(&self) -> ::std::option::Option<&str> {
        self.scaling_group_name.as_deref()
    }
    /// <p>The ARN identifier for the scaling group.</p>
    pub fn scaling_group_arn(&self) -> ::std::option::Option<&str> {
        self.scaling_group_arn.as_deref()
    }
    /// <p>The memory and CPU capabilities of the scaling group host on which FinSpace Managed kdb clusters will be placed.</p>
    /// <p>It can have one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>kx.sg.large</code> – The host type with a configuration of 16 GiB memory and 2 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.xlarge</code> – The host type with a configuration of 32 GiB memory and 4 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.2xlarge</code> – The host type with a configuration of 64 GiB memory and 8 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.4xlarge</code> – The host type with a configuration of 108 GiB memory and 16 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.8xlarge</code> – The host type with a configuration of 216 GiB memory and 32 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.16xlarge</code> – The host type with a configuration of 432 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.32xlarge</code> – The host type with a configuration of 864 GiB memory and 128 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.16xlarge</code> – The host type with a configuration of 1949 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.24xlarge</code> – The host type with a configuration of 2948 GiB memory and 96 vCPUs.</p></li>
    /// </ul>
    pub fn host_type(&self) -> ::std::option::Option<&str> {
        self.host_type.as_deref()
    }
    /// <p>The list of Managed kdb clusters that are currently active in the given scaling group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.clusters.is_none()`.
    pub fn clusters(&self) -> &[::std::string::String] {
        self.clusters.as_deref().unwrap_or_default()
    }
    /// <p>The identifier of the availability zones.</p>
    pub fn availability_zone_id(&self) -> ::std::option::Option<&str> {
        self.availability_zone_id.as_deref()
    }
    /// <p>The status of scaling group.</p>
    /// <ul>
    /// <li>
    /// <p>CREATING – The scaling group creation is in progress.</p></li>
    /// <li>
    /// <p>CREATE_FAILED – The scaling group creation has failed.</p></li>
    /// <li>
    /// <p>ACTIVE – The scaling group is active.</p></li>
    /// <li>
    /// <p>UPDATING – The scaling group is in the process of being updated.</p></li>
    /// <li>
    /// <p>UPDATE_FAILED – The update action failed.</p></li>
    /// <li>
    /// <p>DELETING – The scaling group is in the process of being deleted.</p></li>
    /// <li>
    /// <p>DELETE_FAILED – The system failed to delete the scaling group.</p></li>
    /// <li>
    /// <p>DELETED – The scaling group is successfully deleted.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::KxScalingGroupStatus> {
        self.status.as_ref()
    }
    /// <p>The error message when a failed state occurs.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&str> {
        self.status_reason.as_deref()
    }
    /// <p>The last time that the scaling group was updated in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn last_modified_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_timestamp.as_ref()
    }
    /// <p>The timestamp at which the scaling group was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetKxScalingGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetKxScalingGroupOutput {
    /// Creates a new builder-style object to manufacture [`GetKxScalingGroupOutput`](crate::operation::get_kx_scaling_group::GetKxScalingGroupOutput).
    pub fn builder() -> crate::operation::get_kx_scaling_group::builders::GetKxScalingGroupOutputBuilder {
        crate::operation::get_kx_scaling_group::builders::GetKxScalingGroupOutputBuilder::default()
    }
}

/// A builder for [`GetKxScalingGroupOutput`](crate::operation::get_kx_scaling_group::GetKxScalingGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetKxScalingGroupOutputBuilder {
    pub(crate) scaling_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) scaling_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) host_type: ::std::option::Option<::std::string::String>,
    pub(crate) clusters: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) availability_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::KxScalingGroupStatus>,
    pub(crate) status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetKxScalingGroupOutputBuilder {
    /// <p>A unique identifier for the kdb scaling group.</p>
    pub fn scaling_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scaling_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the kdb scaling group.</p>
    pub fn set_scaling_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scaling_group_name = input;
        self
    }
    /// <p>A unique identifier for the kdb scaling group.</p>
    pub fn get_scaling_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.scaling_group_name
    }
    /// <p>The ARN identifier for the scaling group.</p>
    pub fn scaling_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scaling_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN identifier for the scaling group.</p>
    pub fn set_scaling_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scaling_group_arn = input;
        self
    }
    /// <p>The ARN identifier for the scaling group.</p>
    pub fn get_scaling_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.scaling_group_arn
    }
    /// <p>The memory and CPU capabilities of the scaling group host on which FinSpace Managed kdb clusters will be placed.</p>
    /// <p>It can have one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>kx.sg.large</code> – The host type with a configuration of 16 GiB memory and 2 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.xlarge</code> – The host type with a configuration of 32 GiB memory and 4 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.2xlarge</code> – The host type with a configuration of 64 GiB memory and 8 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.4xlarge</code> – The host type with a configuration of 108 GiB memory and 16 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.8xlarge</code> – The host type with a configuration of 216 GiB memory and 32 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.16xlarge</code> – The host type with a configuration of 432 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.32xlarge</code> – The host type with a configuration of 864 GiB memory and 128 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.16xlarge</code> – The host type with a configuration of 1949 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.24xlarge</code> – The host type with a configuration of 2948 GiB memory and 96 vCPUs.</p></li>
    /// </ul>
    pub fn host_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.host_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The memory and CPU capabilities of the scaling group host on which FinSpace Managed kdb clusters will be placed.</p>
    /// <p>It can have one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>kx.sg.large</code> – The host type with a configuration of 16 GiB memory and 2 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.xlarge</code> – The host type with a configuration of 32 GiB memory and 4 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.2xlarge</code> – The host type with a configuration of 64 GiB memory and 8 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.4xlarge</code> – The host type with a configuration of 108 GiB memory and 16 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.8xlarge</code> – The host type with a configuration of 216 GiB memory and 32 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.16xlarge</code> – The host type with a configuration of 432 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.32xlarge</code> – The host type with a configuration of 864 GiB memory and 128 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.16xlarge</code> – The host type with a configuration of 1949 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.24xlarge</code> – The host type with a configuration of 2948 GiB memory and 96 vCPUs.</p></li>
    /// </ul>
    pub fn set_host_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.host_type = input;
        self
    }
    /// <p>The memory and CPU capabilities of the scaling group host on which FinSpace Managed kdb clusters will be placed.</p>
    /// <p>It can have one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>kx.sg.large</code> – The host type with a configuration of 16 GiB memory and 2 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.xlarge</code> – The host type with a configuration of 32 GiB memory and 4 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.2xlarge</code> – The host type with a configuration of 64 GiB memory and 8 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.4xlarge</code> – The host type with a configuration of 108 GiB memory and 16 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.8xlarge</code> – The host type with a configuration of 216 GiB memory and 32 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.16xlarge</code> – The host type with a configuration of 432 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg.32xlarge</code> – The host type with a configuration of 864 GiB memory and 128 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.16xlarge</code> – The host type with a configuration of 1949 GiB memory and 64 vCPUs.</p></li>
    /// <li>
    /// <p><code>kx.sg1.24xlarge</code> – The host type with a configuration of 2948 GiB memory and 96 vCPUs.</p></li>
    /// </ul>
    pub fn get_host_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.host_type
    }
    /// Appends an item to `clusters`.
    ///
    /// To override the contents of this collection use [`set_clusters`](Self::set_clusters).
    ///
    /// <p>The list of Managed kdb clusters that are currently active in the given scaling group.</p>
    pub fn clusters(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.clusters.unwrap_or_default();
        v.push(input.into());
        self.clusters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of Managed kdb clusters that are currently active in the given scaling group.</p>
    pub fn set_clusters(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.clusters = input;
        self
    }
    /// <p>The list of Managed kdb clusters that are currently active in the given scaling group.</p>
    pub fn get_clusters(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.clusters
    }
    /// <p>The identifier of the availability zones.</p>
    pub fn availability_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the availability zones.</p>
    pub fn set_availability_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone_id = input;
        self
    }
    /// <p>The identifier of the availability zones.</p>
    pub fn get_availability_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone_id
    }
    /// <p>The status of scaling group.</p>
    /// <ul>
    /// <li>
    /// <p>CREATING – The scaling group creation is in progress.</p></li>
    /// <li>
    /// <p>CREATE_FAILED – The scaling group creation has failed.</p></li>
    /// <li>
    /// <p>ACTIVE – The scaling group is active.</p></li>
    /// <li>
    /// <p>UPDATING – The scaling group is in the process of being updated.</p></li>
    /// <li>
    /// <p>UPDATE_FAILED – The update action failed.</p></li>
    /// <li>
    /// <p>DELETING – The scaling group is in the process of being deleted.</p></li>
    /// <li>
    /// <p>DELETE_FAILED – The system failed to delete the scaling group.</p></li>
    /// <li>
    /// <p>DELETED – The scaling group is successfully deleted.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::KxScalingGroupStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of scaling group.</p>
    /// <ul>
    /// <li>
    /// <p>CREATING – The scaling group creation is in progress.</p></li>
    /// <li>
    /// <p>CREATE_FAILED – The scaling group creation has failed.</p></li>
    /// <li>
    /// <p>ACTIVE – The scaling group is active.</p></li>
    /// <li>
    /// <p>UPDATING – The scaling group is in the process of being updated.</p></li>
    /// <li>
    /// <p>UPDATE_FAILED – The update action failed.</p></li>
    /// <li>
    /// <p>DELETING – The scaling group is in the process of being deleted.</p></li>
    /// <li>
    /// <p>DELETE_FAILED – The system failed to delete the scaling group.</p></li>
    /// <li>
    /// <p>DELETED – The scaling group is successfully deleted.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::KxScalingGroupStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of scaling group.</p>
    /// <ul>
    /// <li>
    /// <p>CREATING – The scaling group creation is in progress.</p></li>
    /// <li>
    /// <p>CREATE_FAILED – The scaling group creation has failed.</p></li>
    /// <li>
    /// <p>ACTIVE – The scaling group is active.</p></li>
    /// <li>
    /// <p>UPDATING – The scaling group is in the process of being updated.</p></li>
    /// <li>
    /// <p>UPDATE_FAILED – The update action failed.</p></li>
    /// <li>
    /// <p>DELETING – The scaling group is in the process of being deleted.</p></li>
    /// <li>
    /// <p>DELETE_FAILED – The system failed to delete the scaling group.</p></li>
    /// <li>
    /// <p>DELETED – The scaling group is successfully deleted.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::KxScalingGroupStatus> {
        &self.status
    }
    /// <p>The error message when a failed state occurs.</p>
    pub fn status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message when a failed state occurs.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The error message when a failed state occurs.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_reason
    }
    /// <p>The last time that the scaling group was updated in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn last_modified_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time that the scaling group was updated in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn set_last_modified_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_timestamp = input;
        self
    }
    /// <p>The last time that the scaling group was updated in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn get_last_modified_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_timestamp
    }
    /// <p>The timestamp at which the scaling group was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the scaling group was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The timestamp at which the scaling group was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetKxScalingGroupOutput`](crate::operation::get_kx_scaling_group::GetKxScalingGroupOutput).
    pub fn build(self) -> crate::operation::get_kx_scaling_group::GetKxScalingGroupOutput {
        crate::operation::get_kx_scaling_group::GetKxScalingGroupOutput {
            scaling_group_name: self.scaling_group_name,
            scaling_group_arn: self.scaling_group_arn,
            host_type: self.host_type,
            clusters: self.clusters,
            availability_zone_id: self.availability_zone_id,
            status: self.status,
            status_reason: self.status_reason,
            last_modified_timestamp: self.last_modified_timestamp,
            created_timestamp: self.created_timestamp,
            _request_id: self._request_id,
        }
    }
}

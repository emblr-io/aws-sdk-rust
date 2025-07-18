// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output of the <code>DescribeHapg</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeHapgOutput {
    /// <p>The ARN of the high-availability partition group.</p>
    pub hapg_arn: ::std::option::Option<::std::string::String>,
    /// <p>The serial number of the high-availability partition group.</p>
    pub hapg_serial: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub hsms_last_action_failed: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p></p>
    pub hsms_pending_deletion: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p></p>
    pub hsms_pending_registration: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The label for the high-availability partition group.</p>
    pub label: ::std::option::Option<::std::string::String>,
    /// <p>The date and time the high-availability partition group was last modified.</p>
    pub last_modified_timestamp: ::std::option::Option<::std::string::String>,
    /// <p>The list of partition serial numbers that belong to the high-availability partition group.</p>
    pub partition_serial_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The state of the high-availability partition group.</p>
    pub state: ::std::option::Option<crate::types::CloudHsmObjectState>,
    _request_id: Option<String>,
}
impl DescribeHapgOutput {
    /// <p>The ARN of the high-availability partition group.</p>
    pub fn hapg_arn(&self) -> ::std::option::Option<&str> {
        self.hapg_arn.as_deref()
    }
    /// <p>The serial number of the high-availability partition group.</p>
    pub fn hapg_serial(&self) -> ::std::option::Option<&str> {
        self.hapg_serial.as_deref()
    }
    /// <p></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.hsms_last_action_failed.is_none()`.
    pub fn hsms_last_action_failed(&self) -> &[::std::string::String] {
        self.hsms_last_action_failed.as_deref().unwrap_or_default()
    }
    /// <p></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.hsms_pending_deletion.is_none()`.
    pub fn hsms_pending_deletion(&self) -> &[::std::string::String] {
        self.hsms_pending_deletion.as_deref().unwrap_or_default()
    }
    /// <p></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.hsms_pending_registration.is_none()`.
    pub fn hsms_pending_registration(&self) -> &[::std::string::String] {
        self.hsms_pending_registration.as_deref().unwrap_or_default()
    }
    /// <p>The label for the high-availability partition group.</p>
    pub fn label(&self) -> ::std::option::Option<&str> {
        self.label.as_deref()
    }
    /// <p>The date and time the high-availability partition group was last modified.</p>
    pub fn last_modified_timestamp(&self) -> ::std::option::Option<&str> {
        self.last_modified_timestamp.as_deref()
    }
    /// <p>The list of partition serial numbers that belong to the high-availability partition group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.partition_serial_list.is_none()`.
    pub fn partition_serial_list(&self) -> &[::std::string::String] {
        self.partition_serial_list.as_deref().unwrap_or_default()
    }
    /// <p>The state of the high-availability partition group.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::CloudHsmObjectState> {
        self.state.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeHapgOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeHapgOutput {
    /// Creates a new builder-style object to manufacture [`DescribeHapgOutput`](crate::operation::describe_hapg::DescribeHapgOutput).
    pub fn builder() -> crate::operation::describe_hapg::builders::DescribeHapgOutputBuilder {
        crate::operation::describe_hapg::builders::DescribeHapgOutputBuilder::default()
    }
}

/// A builder for [`DescribeHapgOutput`](crate::operation::describe_hapg::DescribeHapgOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeHapgOutputBuilder {
    pub(crate) hapg_arn: ::std::option::Option<::std::string::String>,
    pub(crate) hapg_serial: ::std::option::Option<::std::string::String>,
    pub(crate) hsms_last_action_failed: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) hsms_pending_deletion: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) hsms_pending_registration: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) label: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_timestamp: ::std::option::Option<::std::string::String>,
    pub(crate) partition_serial_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) state: ::std::option::Option<crate::types::CloudHsmObjectState>,
    _request_id: Option<String>,
}
impl DescribeHapgOutputBuilder {
    /// <p>The ARN of the high-availability partition group.</p>
    pub fn hapg_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hapg_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the high-availability partition group.</p>
    pub fn set_hapg_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hapg_arn = input;
        self
    }
    /// <p>The ARN of the high-availability partition group.</p>
    pub fn get_hapg_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.hapg_arn
    }
    /// <p>The serial number of the high-availability partition group.</p>
    pub fn hapg_serial(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hapg_serial = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The serial number of the high-availability partition group.</p>
    pub fn set_hapg_serial(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hapg_serial = input;
        self
    }
    /// <p>The serial number of the high-availability partition group.</p>
    pub fn get_hapg_serial(&self) -> &::std::option::Option<::std::string::String> {
        &self.hapg_serial
    }
    /// Appends an item to `hsms_last_action_failed`.
    ///
    /// To override the contents of this collection use [`set_hsms_last_action_failed`](Self::set_hsms_last_action_failed).
    ///
    /// <p></p>
    pub fn hsms_last_action_failed(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.hsms_last_action_failed.unwrap_or_default();
        v.push(input.into());
        self.hsms_last_action_failed = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_hsms_last_action_failed(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.hsms_last_action_failed = input;
        self
    }
    /// <p></p>
    pub fn get_hsms_last_action_failed(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.hsms_last_action_failed
    }
    /// Appends an item to `hsms_pending_deletion`.
    ///
    /// To override the contents of this collection use [`set_hsms_pending_deletion`](Self::set_hsms_pending_deletion).
    ///
    /// <p></p>
    pub fn hsms_pending_deletion(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.hsms_pending_deletion.unwrap_or_default();
        v.push(input.into());
        self.hsms_pending_deletion = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_hsms_pending_deletion(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.hsms_pending_deletion = input;
        self
    }
    /// <p></p>
    pub fn get_hsms_pending_deletion(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.hsms_pending_deletion
    }
    /// Appends an item to `hsms_pending_registration`.
    ///
    /// To override the contents of this collection use [`set_hsms_pending_registration`](Self::set_hsms_pending_registration).
    ///
    /// <p></p>
    pub fn hsms_pending_registration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.hsms_pending_registration.unwrap_or_default();
        v.push(input.into());
        self.hsms_pending_registration = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_hsms_pending_registration(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.hsms_pending_registration = input;
        self
    }
    /// <p></p>
    pub fn get_hsms_pending_registration(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.hsms_pending_registration
    }
    /// <p>The label for the high-availability partition group.</p>
    pub fn label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The label for the high-availability partition group.</p>
    pub fn set_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label = input;
        self
    }
    /// <p>The label for the high-availability partition group.</p>
    pub fn get_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.label
    }
    /// <p>The date and time the high-availability partition group was last modified.</p>
    pub fn last_modified_timestamp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_timestamp = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time the high-availability partition group was last modified.</p>
    pub fn set_last_modified_timestamp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_timestamp = input;
        self
    }
    /// <p>The date and time the high-availability partition group was last modified.</p>
    pub fn get_last_modified_timestamp(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_timestamp
    }
    /// Appends an item to `partition_serial_list`.
    ///
    /// To override the contents of this collection use [`set_partition_serial_list`](Self::set_partition_serial_list).
    ///
    /// <p>The list of partition serial numbers that belong to the high-availability partition group.</p>
    pub fn partition_serial_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.partition_serial_list.unwrap_or_default();
        v.push(input.into());
        self.partition_serial_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of partition serial numbers that belong to the high-availability partition group.</p>
    pub fn set_partition_serial_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.partition_serial_list = input;
        self
    }
    /// <p>The list of partition serial numbers that belong to the high-availability partition group.</p>
    pub fn get_partition_serial_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.partition_serial_list
    }
    /// <p>The state of the high-availability partition group.</p>
    pub fn state(mut self, input: crate::types::CloudHsmObjectState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the high-availability partition group.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::CloudHsmObjectState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the high-availability partition group.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::CloudHsmObjectState> {
        &self.state
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeHapgOutput`](crate::operation::describe_hapg::DescribeHapgOutput).
    pub fn build(self) -> crate::operation::describe_hapg::DescribeHapgOutput {
        crate::operation::describe_hapg::DescribeHapgOutput {
            hapg_arn: self.hapg_arn,
            hapg_serial: self.hapg_serial,
            hsms_last_action_failed: self.hsms_last_action_failed,
            hsms_pending_deletion: self.hsms_pending_deletion,
            hsms_pending_registration: self.hsms_pending_registration,
            label: self.label,
            last_modified_timestamp: self.last_modified_timestamp,
            partition_serial_list: self.partition_serial_list,
            state: self.state,
            _request_id: self._request_id,
        }
    }
}

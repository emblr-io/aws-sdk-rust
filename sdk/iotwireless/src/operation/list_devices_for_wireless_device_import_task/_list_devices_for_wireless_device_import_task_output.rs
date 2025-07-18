// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDevicesForWirelessDeviceImportTaskOutput {
    /// <p>The token to use to get the next set of results, or <code>null</code> if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Sidewalk destination that describes the IoT rule to route messages received from devices in an import task that are onboarded to AWS IoT Wireless.</p>
    pub destination_name: ::std::option::Option<::std::string::String>,
    /// <p>List of wireless devices in an import task and their onboarding status.</p>
    pub imported_wireless_device_list: ::std::option::Option<::std::vec::Vec<crate::types::ImportedWirelessDevice>>,
    _request_id: Option<String>,
}
impl ListDevicesForWirelessDeviceImportTaskOutput {
    /// <p>The token to use to get the next set of results, or <code>null</code> if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The name of the Sidewalk destination that describes the IoT rule to route messages received from devices in an import task that are onboarded to AWS IoT Wireless.</p>
    pub fn destination_name(&self) -> ::std::option::Option<&str> {
        self.destination_name.as_deref()
    }
    /// <p>List of wireless devices in an import task and their onboarding status.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.imported_wireless_device_list.is_none()`.
    pub fn imported_wireless_device_list(&self) -> &[crate::types::ImportedWirelessDevice] {
        self.imported_wireless_device_list.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListDevicesForWirelessDeviceImportTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDevicesForWirelessDeviceImportTaskOutput {
    /// Creates a new builder-style object to manufacture [`ListDevicesForWirelessDeviceImportTaskOutput`](crate::operation::list_devices_for_wireless_device_import_task::ListDevicesForWirelessDeviceImportTaskOutput).
    pub fn builder() -> crate::operation::list_devices_for_wireless_device_import_task::builders::ListDevicesForWirelessDeviceImportTaskOutputBuilder
    {
        crate::operation::list_devices_for_wireless_device_import_task::builders::ListDevicesForWirelessDeviceImportTaskOutputBuilder::default()
    }
}

/// A builder for [`ListDevicesForWirelessDeviceImportTaskOutput`](crate::operation::list_devices_for_wireless_device_import_task::ListDevicesForWirelessDeviceImportTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDevicesForWirelessDeviceImportTaskOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) destination_name: ::std::option::Option<::std::string::String>,
    pub(crate) imported_wireless_device_list: ::std::option::Option<::std::vec::Vec<crate::types::ImportedWirelessDevice>>,
    _request_id: Option<String>,
}
impl ListDevicesForWirelessDeviceImportTaskOutputBuilder {
    /// <p>The token to use to get the next set of results, or <code>null</code> if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to get the next set of results, or <code>null</code> if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to get the next set of results, or <code>null</code> if there are no additional results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The name of the Sidewalk destination that describes the IoT rule to route messages received from devices in an import task that are onboarded to AWS IoT Wireless.</p>
    pub fn destination_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Sidewalk destination that describes the IoT rule to route messages received from devices in an import task that are onboarded to AWS IoT Wireless.</p>
    pub fn set_destination_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_name = input;
        self
    }
    /// <p>The name of the Sidewalk destination that describes the IoT rule to route messages received from devices in an import task that are onboarded to AWS IoT Wireless.</p>
    pub fn get_destination_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_name
    }
    /// Appends an item to `imported_wireless_device_list`.
    ///
    /// To override the contents of this collection use [`set_imported_wireless_device_list`](Self::set_imported_wireless_device_list).
    ///
    /// <p>List of wireless devices in an import task and their onboarding status.</p>
    pub fn imported_wireless_device_list(mut self, input: crate::types::ImportedWirelessDevice) -> Self {
        let mut v = self.imported_wireless_device_list.unwrap_or_default();
        v.push(input);
        self.imported_wireless_device_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of wireless devices in an import task and their onboarding status.</p>
    pub fn set_imported_wireless_device_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ImportedWirelessDevice>>) -> Self {
        self.imported_wireless_device_list = input;
        self
    }
    /// <p>List of wireless devices in an import task and their onboarding status.</p>
    pub fn get_imported_wireless_device_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ImportedWirelessDevice>> {
        &self.imported_wireless_device_list
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDevicesForWirelessDeviceImportTaskOutput`](crate::operation::list_devices_for_wireless_device_import_task::ListDevicesForWirelessDeviceImportTaskOutput).
    pub fn build(self) -> crate::operation::list_devices_for_wireless_device_import_task::ListDevicesForWirelessDeviceImportTaskOutput {
        crate::operation::list_devices_for_wireless_device_import_task::ListDevicesForWirelessDeviceImportTaskOutput {
            next_token: self.next_token,
            destination_name: self.destination_name,
            imported_wireless_device_list: self.imported_wireless_device_list,
            _request_id: self._request_id,
        }
    }
}

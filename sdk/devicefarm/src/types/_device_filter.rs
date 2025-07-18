// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a device filter used to select a set of devices to be included in a test run. This data structure is passed in as the <code>deviceSelectionConfiguration</code> parameter to <code>ScheduleRun</code>. For an example of the JSON request syntax, see <code>ScheduleRun</code>.</p>
/// <p>It is also passed in as the <code>filters</code> parameter to <code>ListDevices</code>. For an example of the JSON request syntax, see <code>ListDevices</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeviceFilter {
    /// <p>The aspect of a device such as platform or model used as the selection criteria in a device filter.</p>
    /// <p>The supported operators for each attribute are provided in the following list.</p>
    /// <dl>
    /// <dt>
    /// ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device (for example, <code>arn:aws:devicefarm:us-west-2::device:12345Example</code>).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// PLATFORM
    /// </dt>
    /// <dd>
    /// <p>The device platform. Valid values are ANDROID or IOS.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// OS_VERSION
    /// </dt>
    /// <dd>
    /// <p>The operating system version (for example, 10.3.2).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>GREATER_THAN</code>, <code>GREATER_THAN_OR_EQUALS</code>, <code>IN</code>, <code>LESS_THAN</code>, <code>LESS_THAN_OR_EQUALS</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// MODEL
    /// </dt>
    /// <dd>
    /// <p>The device model (for example, iPad 5th Gen).</p>
    /// <p>Supported operators: <code>CONTAINS</code>, <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// AVAILABILITY
    /// </dt>
    /// <dd>
    /// <p>The current availability of the device. Valid values are AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// FORM_FACTOR
    /// </dt>
    /// <dd>
    /// <p>The device form factor. Valid values are PHONE or TABLET.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// MANUFACTURER
    /// </dt>
    /// <dd>
    /// <p>The device manufacturer (for example, Apple).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_ACCESS_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote access. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_DEBUG_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote debugging. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// <p>Because remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>, this filter is ignored.</p>
    /// </dd>
    /// <dt>
    /// INSTANCE_ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device instance.</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// INSTANCE_LABELS
    /// </dt>
    /// <dd>
    /// <p>The label of the device instance.</p>
    /// <p>Supported operators: <code>CONTAINS</code></p>
    /// </dd>
    /// <dt>
    /// FLEET_TYPE
    /// </dt>
    /// <dd>
    /// <p>The fleet type. Valid values are PUBLIC or PRIVATE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// </dl>
    pub attribute: crate::types::DeviceFilterAttribute,
    /// <p>Specifies how Device Farm compares the filter's attribute to the value. See the attribute descriptions.</p>
    pub operator: crate::types::RuleOperator,
    /// <p>An array of one or more filter values used in a device filter.</p>
    /// <p class="title"><b>Operator Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The IN and NOT_IN operators can take a values array that has more than one element.</p></li>
    /// <li>
    /// <p>The other operators require an array with a single element.</p></li>
    /// </ul>
    /// <p class="title"><b>Attribute Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The PLATFORM attribute can be set to ANDROID or IOS.</p></li>
    /// <li>
    /// <p>The AVAILABILITY attribute can be set to AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p></li>
    /// <li>
    /// <p>The FORM_FACTOR attribute can be set to PHONE or TABLET.</p></li>
    /// <li>
    /// <p>The FLEET_TYPE attribute can be set to PUBLIC or PRIVATE.</p></li>
    /// </ul>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl DeviceFilter {
    /// <p>The aspect of a device such as platform or model used as the selection criteria in a device filter.</p>
    /// <p>The supported operators for each attribute are provided in the following list.</p>
    /// <dl>
    /// <dt>
    /// ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device (for example, <code>arn:aws:devicefarm:us-west-2::device:12345Example</code>).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// PLATFORM
    /// </dt>
    /// <dd>
    /// <p>The device platform. Valid values are ANDROID or IOS.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// OS_VERSION
    /// </dt>
    /// <dd>
    /// <p>The operating system version (for example, 10.3.2).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>GREATER_THAN</code>, <code>GREATER_THAN_OR_EQUALS</code>, <code>IN</code>, <code>LESS_THAN</code>, <code>LESS_THAN_OR_EQUALS</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// MODEL
    /// </dt>
    /// <dd>
    /// <p>The device model (for example, iPad 5th Gen).</p>
    /// <p>Supported operators: <code>CONTAINS</code>, <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// AVAILABILITY
    /// </dt>
    /// <dd>
    /// <p>The current availability of the device. Valid values are AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// FORM_FACTOR
    /// </dt>
    /// <dd>
    /// <p>The device form factor. Valid values are PHONE or TABLET.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// MANUFACTURER
    /// </dt>
    /// <dd>
    /// <p>The device manufacturer (for example, Apple).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_ACCESS_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote access. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_DEBUG_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote debugging. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// <p>Because remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>, this filter is ignored.</p>
    /// </dd>
    /// <dt>
    /// INSTANCE_ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device instance.</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// INSTANCE_LABELS
    /// </dt>
    /// <dd>
    /// <p>The label of the device instance.</p>
    /// <p>Supported operators: <code>CONTAINS</code></p>
    /// </dd>
    /// <dt>
    /// FLEET_TYPE
    /// </dt>
    /// <dd>
    /// <p>The fleet type. Valid values are PUBLIC or PRIVATE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// </dl>
    pub fn attribute(&self) -> &crate::types::DeviceFilterAttribute {
        &self.attribute
    }
    /// <p>Specifies how Device Farm compares the filter's attribute to the value. See the attribute descriptions.</p>
    pub fn operator(&self) -> &crate::types::RuleOperator {
        &self.operator
    }
    /// <p>An array of one or more filter values used in a device filter.</p>
    /// <p class="title"><b>Operator Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The IN and NOT_IN operators can take a values array that has more than one element.</p></li>
    /// <li>
    /// <p>The other operators require an array with a single element.</p></li>
    /// </ul>
    /// <p class="title"><b>Attribute Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The PLATFORM attribute can be set to ANDROID or IOS.</p></li>
    /// <li>
    /// <p>The AVAILABILITY attribute can be set to AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p></li>
    /// <li>
    /// <p>The FORM_FACTOR attribute can be set to PHONE or TABLET.</p></li>
    /// <li>
    /// <p>The FLEET_TYPE attribute can be set to PUBLIC or PRIVATE.</p></li>
    /// </ul>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl DeviceFilter {
    /// Creates a new builder-style object to manufacture [`DeviceFilter`](crate::types::DeviceFilter).
    pub fn builder() -> crate::types::builders::DeviceFilterBuilder {
        crate::types::builders::DeviceFilterBuilder::default()
    }
}

/// A builder for [`DeviceFilter`](crate::types::DeviceFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeviceFilterBuilder {
    pub(crate) attribute: ::std::option::Option<crate::types::DeviceFilterAttribute>,
    pub(crate) operator: ::std::option::Option<crate::types::RuleOperator>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeviceFilterBuilder {
    /// <p>The aspect of a device such as platform or model used as the selection criteria in a device filter.</p>
    /// <p>The supported operators for each attribute are provided in the following list.</p>
    /// <dl>
    /// <dt>
    /// ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device (for example, <code>arn:aws:devicefarm:us-west-2::device:12345Example</code>).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// PLATFORM
    /// </dt>
    /// <dd>
    /// <p>The device platform. Valid values are ANDROID or IOS.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// OS_VERSION
    /// </dt>
    /// <dd>
    /// <p>The operating system version (for example, 10.3.2).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>GREATER_THAN</code>, <code>GREATER_THAN_OR_EQUALS</code>, <code>IN</code>, <code>LESS_THAN</code>, <code>LESS_THAN_OR_EQUALS</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// MODEL
    /// </dt>
    /// <dd>
    /// <p>The device model (for example, iPad 5th Gen).</p>
    /// <p>Supported operators: <code>CONTAINS</code>, <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// AVAILABILITY
    /// </dt>
    /// <dd>
    /// <p>The current availability of the device. Valid values are AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// FORM_FACTOR
    /// </dt>
    /// <dd>
    /// <p>The device form factor. Valid values are PHONE or TABLET.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// MANUFACTURER
    /// </dt>
    /// <dd>
    /// <p>The device manufacturer (for example, Apple).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_ACCESS_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote access. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_DEBUG_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote debugging. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// <p>Because remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>, this filter is ignored.</p>
    /// </dd>
    /// <dt>
    /// INSTANCE_ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device instance.</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// INSTANCE_LABELS
    /// </dt>
    /// <dd>
    /// <p>The label of the device instance.</p>
    /// <p>Supported operators: <code>CONTAINS</code></p>
    /// </dd>
    /// <dt>
    /// FLEET_TYPE
    /// </dt>
    /// <dd>
    /// <p>The fleet type. Valid values are PUBLIC or PRIVATE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// </dl>
    /// This field is required.
    pub fn attribute(mut self, input: crate::types::DeviceFilterAttribute) -> Self {
        self.attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aspect of a device such as platform or model used as the selection criteria in a device filter.</p>
    /// <p>The supported operators for each attribute are provided in the following list.</p>
    /// <dl>
    /// <dt>
    /// ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device (for example, <code>arn:aws:devicefarm:us-west-2::device:12345Example</code>).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// PLATFORM
    /// </dt>
    /// <dd>
    /// <p>The device platform. Valid values are ANDROID or IOS.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// OS_VERSION
    /// </dt>
    /// <dd>
    /// <p>The operating system version (for example, 10.3.2).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>GREATER_THAN</code>, <code>GREATER_THAN_OR_EQUALS</code>, <code>IN</code>, <code>LESS_THAN</code>, <code>LESS_THAN_OR_EQUALS</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// MODEL
    /// </dt>
    /// <dd>
    /// <p>The device model (for example, iPad 5th Gen).</p>
    /// <p>Supported operators: <code>CONTAINS</code>, <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// AVAILABILITY
    /// </dt>
    /// <dd>
    /// <p>The current availability of the device. Valid values are AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// FORM_FACTOR
    /// </dt>
    /// <dd>
    /// <p>The device form factor. Valid values are PHONE or TABLET.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// MANUFACTURER
    /// </dt>
    /// <dd>
    /// <p>The device manufacturer (for example, Apple).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_ACCESS_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote access. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_DEBUG_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote debugging. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// <p>Because remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>, this filter is ignored.</p>
    /// </dd>
    /// <dt>
    /// INSTANCE_ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device instance.</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// INSTANCE_LABELS
    /// </dt>
    /// <dd>
    /// <p>The label of the device instance.</p>
    /// <p>Supported operators: <code>CONTAINS</code></p>
    /// </dd>
    /// <dt>
    /// FLEET_TYPE
    /// </dt>
    /// <dd>
    /// <p>The fleet type. Valid values are PUBLIC or PRIVATE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// </dl>
    pub fn set_attribute(mut self, input: ::std::option::Option<crate::types::DeviceFilterAttribute>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The aspect of a device such as platform or model used as the selection criteria in a device filter.</p>
    /// <p>The supported operators for each attribute are provided in the following list.</p>
    /// <dl>
    /// <dt>
    /// ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device (for example, <code>arn:aws:devicefarm:us-west-2::device:12345Example</code>).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// PLATFORM
    /// </dt>
    /// <dd>
    /// <p>The device platform. Valid values are ANDROID or IOS.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// OS_VERSION
    /// </dt>
    /// <dd>
    /// <p>The operating system version (for example, 10.3.2).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>GREATER_THAN</code>, <code>GREATER_THAN_OR_EQUALS</code>, <code>IN</code>, <code>LESS_THAN</code>, <code>LESS_THAN_OR_EQUALS</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// MODEL
    /// </dt>
    /// <dd>
    /// <p>The device model (for example, iPad 5th Gen).</p>
    /// <p>Supported operators: <code>CONTAINS</code>, <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// AVAILABILITY
    /// </dt>
    /// <dd>
    /// <p>The current availability of the device. Valid values are AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// FORM_FACTOR
    /// </dt>
    /// <dd>
    /// <p>The device form factor. Valid values are PHONE or TABLET.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// MANUFACTURER
    /// </dt>
    /// <dd>
    /// <p>The device manufacturer (for example, Apple).</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_ACCESS_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote access. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// <dt>
    /// REMOTE_DEBUG_ENABLED
    /// </dt>
    /// <dd>
    /// <p>Whether the device is enabled for remote debugging. Valid values are TRUE or FALSE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// <p>Because remote debugging is <a href="https://docs.aws.amazon.com/devicefarm/latest/developerguide/history.html">no longer supported</a>, this filter is ignored.</p>
    /// </dd>
    /// <dt>
    /// INSTANCE_ARN
    /// </dt>
    /// <dd>
    /// <p>The Amazon Resource Name (ARN) of the device instance.</p>
    /// <p>Supported operators: <code>EQUALS</code>, <code>IN</code>, <code>NOT_IN</code></p>
    /// </dd>
    /// <dt>
    /// INSTANCE_LABELS
    /// </dt>
    /// <dd>
    /// <p>The label of the device instance.</p>
    /// <p>Supported operators: <code>CONTAINS</code></p>
    /// </dd>
    /// <dt>
    /// FLEET_TYPE
    /// </dt>
    /// <dd>
    /// <p>The fleet type. Valid values are PUBLIC or PRIVATE.</p>
    /// <p>Supported operators: <code>EQUALS</code></p>
    /// </dd>
    /// </dl>
    pub fn get_attribute(&self) -> &::std::option::Option<crate::types::DeviceFilterAttribute> {
        &self.attribute
    }
    /// <p>Specifies how Device Farm compares the filter's attribute to the value. See the attribute descriptions.</p>
    /// This field is required.
    pub fn operator(mut self, input: crate::types::RuleOperator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies how Device Farm compares the filter's attribute to the value. See the attribute descriptions.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::RuleOperator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>Specifies how Device Farm compares the filter's attribute to the value. See the attribute descriptions.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::RuleOperator> {
        &self.operator
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>An array of one or more filter values used in a device filter.</p>
    /// <p class="title"><b>Operator Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The IN and NOT_IN operators can take a values array that has more than one element.</p></li>
    /// <li>
    /// <p>The other operators require an array with a single element.</p></li>
    /// </ul>
    /// <p class="title"><b>Attribute Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The PLATFORM attribute can be set to ANDROID or IOS.</p></li>
    /// <li>
    /// <p>The AVAILABILITY attribute can be set to AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p></li>
    /// <li>
    /// <p>The FORM_FACTOR attribute can be set to PHONE or TABLET.</p></li>
    /// <li>
    /// <p>The FLEET_TYPE attribute can be set to PUBLIC or PRIVATE.</p></li>
    /// </ul>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of one or more filter values used in a device filter.</p>
    /// <p class="title"><b>Operator Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The IN and NOT_IN operators can take a values array that has more than one element.</p></li>
    /// <li>
    /// <p>The other operators require an array with a single element.</p></li>
    /// </ul>
    /// <p class="title"><b>Attribute Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The PLATFORM attribute can be set to ANDROID or IOS.</p></li>
    /// <li>
    /// <p>The AVAILABILITY attribute can be set to AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p></li>
    /// <li>
    /// <p>The FORM_FACTOR attribute can be set to PHONE or TABLET.</p></li>
    /// <li>
    /// <p>The FLEET_TYPE attribute can be set to PUBLIC or PRIVATE.</p></li>
    /// </ul>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>An array of one or more filter values used in a device filter.</p>
    /// <p class="title"><b>Operator Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The IN and NOT_IN operators can take a values array that has more than one element.</p></li>
    /// <li>
    /// <p>The other operators require an array with a single element.</p></li>
    /// </ul>
    /// <p class="title"><b>Attribute Values</b></p>
    /// <ul>
    /// <li>
    /// <p>The PLATFORM attribute can be set to ANDROID or IOS.</p></li>
    /// <li>
    /// <p>The AVAILABILITY attribute can be set to AVAILABLE, HIGHLY_AVAILABLE, BUSY, or TEMPORARY_NOT_AVAILABLE.</p></li>
    /// <li>
    /// <p>The FORM_FACTOR attribute can be set to PHONE or TABLET.</p></li>
    /// <li>
    /// <p>The FLEET_TYPE attribute can be set to PUBLIC or PRIVATE.</p></li>
    /// </ul>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`DeviceFilter`](crate::types::DeviceFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`attribute`](crate::types::builders::DeviceFilterBuilder::attribute)
    /// - [`operator`](crate::types::builders::DeviceFilterBuilder::operator)
    /// - [`values`](crate::types::builders::DeviceFilterBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::DeviceFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DeviceFilter {
            attribute: self.attribute.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute",
                    "attribute was not specified but it is required when building DeviceFilter",
                )
            })?,
            operator: self.operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operator",
                    "operator was not specified but it is required when building DeviceFilter",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building DeviceFilter",
                )
            })?,
        })
    }
}

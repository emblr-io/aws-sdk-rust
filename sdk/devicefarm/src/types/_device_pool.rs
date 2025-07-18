// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a collection of device types.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DevicePool {
    /// <p>The device pool's ARN.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The device pool's name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The device pool's description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The device pool's type.</p>
    /// <p>Allowed values include:</p>
    /// <ul>
    /// <li>
    /// <p>CURATED: A device pool that is created and managed by AWS Device Farm.</p></li>
    /// <li>
    /// <p>PRIVATE: A device pool that is created and managed by the device pool developer.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::DevicePoolType>,
    /// <p>Information about the device pool's rules.</p>
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    /// <p>The number of devices that Device Farm can add to your device pool. Device Farm adds devices that are available and meet the criteria that you assign for the <code>rules</code> parameter. Depending on how many devices meet these constraints, your device pool might contain fewer devices than the value for this parameter.</p>
    /// <p>By specifying the maximum number of devices, you can control the costs that you incur by running tests.</p>
    pub max_devices: ::std::option::Option<i32>,
}
impl DevicePool {
    /// <p>The device pool's ARN.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The device pool's name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The device pool's description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The device pool's type.</p>
    /// <p>Allowed values include:</p>
    /// <ul>
    /// <li>
    /// <p>CURATED: A device pool that is created and managed by AWS Device Farm.</p></li>
    /// <li>
    /// <p>PRIVATE: A device pool that is created and managed by the device pool developer.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::DevicePoolType> {
        self.r#type.as_ref()
    }
    /// <p>Information about the device pool's rules.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::Rule] {
        self.rules.as_deref().unwrap_or_default()
    }
    /// <p>The number of devices that Device Farm can add to your device pool. Device Farm adds devices that are available and meet the criteria that you assign for the <code>rules</code> parameter. Depending on how many devices meet these constraints, your device pool might contain fewer devices than the value for this parameter.</p>
    /// <p>By specifying the maximum number of devices, you can control the costs that you incur by running tests.</p>
    pub fn max_devices(&self) -> ::std::option::Option<i32> {
        self.max_devices
    }
}
impl DevicePool {
    /// Creates a new builder-style object to manufacture [`DevicePool`](crate::types::DevicePool).
    pub fn builder() -> crate::types::builders::DevicePoolBuilder {
        crate::types::builders::DevicePoolBuilder::default()
    }
}

/// A builder for [`DevicePool`](crate::types::DevicePool).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DevicePoolBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::DevicePoolType>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    pub(crate) max_devices: ::std::option::Option<i32>,
}
impl DevicePoolBuilder {
    /// <p>The device pool's ARN.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device pool's ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The device pool's ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The device pool's name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device pool's name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The device pool's name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The device pool's description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device pool's description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The device pool's description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The device pool's type.</p>
    /// <p>Allowed values include:</p>
    /// <ul>
    /// <li>
    /// <p>CURATED: A device pool that is created and managed by AWS Device Farm.</p></li>
    /// <li>
    /// <p>PRIVATE: A device pool that is created and managed by the device pool developer.</p></li>
    /// </ul>
    pub fn r#type(mut self, input: crate::types::DevicePoolType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The device pool's type.</p>
    /// <p>Allowed values include:</p>
    /// <ul>
    /// <li>
    /// <p>CURATED: A device pool that is created and managed by AWS Device Farm.</p></li>
    /// <li>
    /// <p>PRIVATE: A device pool that is created and managed by the device pool developer.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DevicePoolType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The device pool's type.</p>
    /// <p>Allowed values include:</p>
    /// <ul>
    /// <li>
    /// <p>CURATED: A device pool that is created and managed by AWS Device Farm.</p></li>
    /// <li>
    /// <p>PRIVATE: A device pool that is created and managed by the device pool developer.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DevicePoolType> {
        &self.r#type
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// <p>Information about the device pool's rules.</p>
    pub fn rules(mut self, input: crate::types::Rule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the device pool's rules.</p>
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>) -> Self {
        self.rules = input;
        self
    }
    /// <p>Information about the device pool's rules.</p>
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Rule>> {
        &self.rules
    }
    /// <p>The number of devices that Device Farm can add to your device pool. Device Farm adds devices that are available and meet the criteria that you assign for the <code>rules</code> parameter. Depending on how many devices meet these constraints, your device pool might contain fewer devices than the value for this parameter.</p>
    /// <p>By specifying the maximum number of devices, you can control the costs that you incur by running tests.</p>
    pub fn max_devices(mut self, input: i32) -> Self {
        self.max_devices = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of devices that Device Farm can add to your device pool. Device Farm adds devices that are available and meet the criteria that you assign for the <code>rules</code> parameter. Depending on how many devices meet these constraints, your device pool might contain fewer devices than the value for this parameter.</p>
    /// <p>By specifying the maximum number of devices, you can control the costs that you incur by running tests.</p>
    pub fn set_max_devices(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_devices = input;
        self
    }
    /// <p>The number of devices that Device Farm can add to your device pool. Device Farm adds devices that are available and meet the criteria that you assign for the <code>rules</code> parameter. Depending on how many devices meet these constraints, your device pool might contain fewer devices than the value for this parameter.</p>
    /// <p>By specifying the maximum number of devices, you can control the costs that you incur by running tests.</p>
    pub fn get_max_devices(&self) -> &::std::option::Option<i32> {
        &self.max_devices
    }
    /// Consumes the builder and constructs a [`DevicePool`](crate::types::DevicePool).
    pub fn build(self) -> crate::types::DevicePool {
        crate::types::DevicePool {
            arn: self.arn,
            name: self.name,
            description: self.description,
            r#type: self.r#type,
            rules: self.rules,
            max_devices: self.max_devices,
        }
    }
}

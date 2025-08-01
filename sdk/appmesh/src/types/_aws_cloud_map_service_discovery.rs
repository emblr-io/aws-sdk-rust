// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the Cloud Map service discovery information for your virtual node.</p><note>
/// <p>Cloud Map is not available in the eu-south-1 Region.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsCloudMapServiceDiscovery {
    /// <p>The name of the Cloud Map namespace to use.</p>
    pub namespace_name: ::std::string::String,
    /// <p>The name of the Cloud Map service to use.</p>
    pub service_name: ::std::string::String,
    /// <p>A string map that contains attributes with values that you can use to filter instances by any custom attribute that you specified when you registered the instance. Only instances that match all of the specified key/value pairs will be returned.</p>
    pub attributes: ::std::option::Option<::std::vec::Vec<crate::types::AwsCloudMapInstanceAttribute>>,
    /// <p>The preferred IP version that this virtual node uses. Setting the IP preference on the virtual node only overrides the IP preference set for the mesh on this specific node.</p>
    pub ip_preference: ::std::option::Option<crate::types::IpPreference>,
}
impl AwsCloudMapServiceDiscovery {
    /// <p>The name of the Cloud Map namespace to use.</p>
    pub fn namespace_name(&self) -> &str {
        use std::ops::Deref;
        self.namespace_name.deref()
    }
    /// <p>The name of the Cloud Map service to use.</p>
    pub fn service_name(&self) -> &str {
        use std::ops::Deref;
        self.service_name.deref()
    }
    /// <p>A string map that contains attributes with values that you can use to filter instances by any custom attribute that you specified when you registered the instance. Only instances that match all of the specified key/value pairs will be returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes.is_none()`.
    pub fn attributes(&self) -> &[crate::types::AwsCloudMapInstanceAttribute] {
        self.attributes.as_deref().unwrap_or_default()
    }
    /// <p>The preferred IP version that this virtual node uses. Setting the IP preference on the virtual node only overrides the IP preference set for the mesh on this specific node.</p>
    pub fn ip_preference(&self) -> ::std::option::Option<&crate::types::IpPreference> {
        self.ip_preference.as_ref()
    }
}
impl AwsCloudMapServiceDiscovery {
    /// Creates a new builder-style object to manufacture [`AwsCloudMapServiceDiscovery`](crate::types::AwsCloudMapServiceDiscovery).
    pub fn builder() -> crate::types::builders::AwsCloudMapServiceDiscoveryBuilder {
        crate::types::builders::AwsCloudMapServiceDiscoveryBuilder::default()
    }
}

/// A builder for [`AwsCloudMapServiceDiscovery`](crate::types::AwsCloudMapServiceDiscovery).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsCloudMapServiceDiscoveryBuilder {
    pub(crate) namespace_name: ::std::option::Option<::std::string::String>,
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
    pub(crate) attributes: ::std::option::Option<::std::vec::Vec<crate::types::AwsCloudMapInstanceAttribute>>,
    pub(crate) ip_preference: ::std::option::Option<crate::types::IpPreference>,
}
impl AwsCloudMapServiceDiscoveryBuilder {
    /// <p>The name of the Cloud Map namespace to use.</p>
    /// This field is required.
    pub fn namespace_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Cloud Map namespace to use.</p>
    pub fn set_namespace_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace_name = input;
        self
    }
    /// <p>The name of the Cloud Map namespace to use.</p>
    pub fn get_namespace_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace_name
    }
    /// <p>The name of the Cloud Map service to use.</p>
    /// This field is required.
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Cloud Map service to use.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>The name of the Cloud Map service to use.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// Appends an item to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>A string map that contains attributes with values that you can use to filter instances by any custom attribute that you specified when you registered the instance. Only instances that match all of the specified key/value pairs will be returned.</p>
    pub fn attributes(mut self, input: crate::types::AwsCloudMapInstanceAttribute) -> Self {
        let mut v = self.attributes.unwrap_or_default();
        v.push(input);
        self.attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A string map that contains attributes with values that you can use to filter instances by any custom attribute that you specified when you registered the instance. Only instances that match all of the specified key/value pairs will be returned.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AwsCloudMapInstanceAttribute>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>A string map that contains attributes with values that you can use to filter instances by any custom attribute that you specified when you registered the instance. Only instances that match all of the specified key/value pairs will be returned.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsCloudMapInstanceAttribute>> {
        &self.attributes
    }
    /// <p>The preferred IP version that this virtual node uses. Setting the IP preference on the virtual node only overrides the IP preference set for the mesh on this specific node.</p>
    pub fn ip_preference(mut self, input: crate::types::IpPreference) -> Self {
        self.ip_preference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The preferred IP version that this virtual node uses. Setting the IP preference on the virtual node only overrides the IP preference set for the mesh on this specific node.</p>
    pub fn set_ip_preference(mut self, input: ::std::option::Option<crate::types::IpPreference>) -> Self {
        self.ip_preference = input;
        self
    }
    /// <p>The preferred IP version that this virtual node uses. Setting the IP preference on the virtual node only overrides the IP preference set for the mesh on this specific node.</p>
    pub fn get_ip_preference(&self) -> &::std::option::Option<crate::types::IpPreference> {
        &self.ip_preference
    }
    /// Consumes the builder and constructs a [`AwsCloudMapServiceDiscovery`](crate::types::AwsCloudMapServiceDiscovery).
    /// This method will fail if any of the following fields are not set:
    /// - [`namespace_name`](crate::types::builders::AwsCloudMapServiceDiscoveryBuilder::namespace_name)
    /// - [`service_name`](crate::types::builders::AwsCloudMapServiceDiscoveryBuilder::service_name)
    pub fn build(self) -> ::std::result::Result<crate::types::AwsCloudMapServiceDiscovery, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AwsCloudMapServiceDiscovery {
            namespace_name: self.namespace_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "namespace_name",
                    "namespace_name was not specified but it is required when building AwsCloudMapServiceDiscovery",
                )
            })?,
            service_name: self.service_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_name",
                    "service_name was not specified but it is required when building AwsCloudMapServiceDiscovery",
                )
            })?,
            attributes: self.attributes,
            ip_preference: self.ip_preference,
        })
    }
}

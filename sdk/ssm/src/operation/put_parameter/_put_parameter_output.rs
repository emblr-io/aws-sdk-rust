// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutParameterOutput {
    /// <p>The new version number of a parameter. If you edit a parameter value, Parameter Store automatically creates a new version and assigns this new version a unique ID. You can reference a parameter version ID in API operations or in Systems Manager documents (SSM documents). By default, if you don't specify a specific version, the system returns the latest parameter value when a parameter is called.</p>
    pub version: i64,
    /// <p>The tier assigned to the parameter.</p>
    pub tier: ::std::option::Option<crate::types::ParameterTier>,
    _request_id: Option<String>,
}
impl PutParameterOutput {
    /// <p>The new version number of a parameter. If you edit a parameter value, Parameter Store automatically creates a new version and assigns this new version a unique ID. You can reference a parameter version ID in API operations or in Systems Manager documents (SSM documents). By default, if you don't specify a specific version, the system returns the latest parameter value when a parameter is called.</p>
    pub fn version(&self) -> i64 {
        self.version
    }
    /// <p>The tier assigned to the parameter.</p>
    pub fn tier(&self) -> ::std::option::Option<&crate::types::ParameterTier> {
        self.tier.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutParameterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutParameterOutput {
    /// Creates a new builder-style object to manufacture [`PutParameterOutput`](crate::operation::put_parameter::PutParameterOutput).
    pub fn builder() -> crate::operation::put_parameter::builders::PutParameterOutputBuilder {
        crate::operation::put_parameter::builders::PutParameterOutputBuilder::default()
    }
}

/// A builder for [`PutParameterOutput`](crate::operation::put_parameter::PutParameterOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutParameterOutputBuilder {
    pub(crate) version: ::std::option::Option<i64>,
    pub(crate) tier: ::std::option::Option<crate::types::ParameterTier>,
    _request_id: Option<String>,
}
impl PutParameterOutputBuilder {
    /// <p>The new version number of a parameter. If you edit a parameter value, Parameter Store automatically creates a new version and assigns this new version a unique ID. You can reference a parameter version ID in API operations or in Systems Manager documents (SSM documents). By default, if you don't specify a specific version, the system returns the latest parameter value when a parameter is called.</p>
    pub fn version(mut self, input: i64) -> Self {
        self.version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new version number of a parameter. If you edit a parameter value, Parameter Store automatically creates a new version and assigns this new version a unique ID. You can reference a parameter version ID in API operations or in Systems Manager documents (SSM documents). By default, if you don't specify a specific version, the system returns the latest parameter value when a parameter is called.</p>
    pub fn set_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version = input;
        self
    }
    /// <p>The new version number of a parameter. If you edit a parameter value, Parameter Store automatically creates a new version and assigns this new version a unique ID. You can reference a parameter version ID in API operations or in Systems Manager documents (SSM documents). By default, if you don't specify a specific version, the system returns the latest parameter value when a parameter is called.</p>
    pub fn get_version(&self) -> &::std::option::Option<i64> {
        &self.version
    }
    /// <p>The tier assigned to the parameter.</p>
    pub fn tier(mut self, input: crate::types::ParameterTier) -> Self {
        self.tier = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tier assigned to the parameter.</p>
    pub fn set_tier(mut self, input: ::std::option::Option<crate::types::ParameterTier>) -> Self {
        self.tier = input;
        self
    }
    /// <p>The tier assigned to the parameter.</p>
    pub fn get_tier(&self) -> &::std::option::Option<crate::types::ParameterTier> {
        &self.tier
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutParameterOutput`](crate::operation::put_parameter::PutParameterOutput).
    pub fn build(self) -> crate::operation::put_parameter::PutParameterOutput {
        crate::operation::put_parameter::PutParameterOutput {
            version: self.version.unwrap_or_default(),
            tier: self.tier,
            _request_id: self._request_id,
        }
    }
}

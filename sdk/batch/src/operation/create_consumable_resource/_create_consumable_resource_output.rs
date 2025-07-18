// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConsumableResourceOutput {
    /// <p>The name of the consumable resource.</p>
    pub consumable_resource_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the consumable resource.</p>
    pub consumable_resource_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateConsumableResourceOutput {
    /// <p>The name of the consumable resource.</p>
    pub fn consumable_resource_name(&self) -> ::std::option::Option<&str> {
        self.consumable_resource_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the consumable resource.</p>
    pub fn consumable_resource_arn(&self) -> ::std::option::Option<&str> {
        self.consumable_resource_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateConsumableResourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateConsumableResourceOutput {
    /// Creates a new builder-style object to manufacture [`CreateConsumableResourceOutput`](crate::operation::create_consumable_resource::CreateConsumableResourceOutput).
    pub fn builder() -> crate::operation::create_consumable_resource::builders::CreateConsumableResourceOutputBuilder {
        crate::operation::create_consumable_resource::builders::CreateConsumableResourceOutputBuilder::default()
    }
}

/// A builder for [`CreateConsumableResourceOutput`](crate::operation::create_consumable_resource::CreateConsumableResourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConsumableResourceOutputBuilder {
    pub(crate) consumable_resource_name: ::std::option::Option<::std::string::String>,
    pub(crate) consumable_resource_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateConsumableResourceOutputBuilder {
    /// <p>The name of the consumable resource.</p>
    /// This field is required.
    pub fn consumable_resource_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.consumable_resource_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the consumable resource.</p>
    pub fn set_consumable_resource_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.consumable_resource_name = input;
        self
    }
    /// <p>The name of the consumable resource.</p>
    pub fn get_consumable_resource_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.consumable_resource_name
    }
    /// <p>The Amazon Resource Name (ARN) of the consumable resource.</p>
    /// This field is required.
    pub fn consumable_resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.consumable_resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the consumable resource.</p>
    pub fn set_consumable_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.consumable_resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the consumable resource.</p>
    pub fn get_consumable_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.consumable_resource_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateConsumableResourceOutput`](crate::operation::create_consumable_resource::CreateConsumableResourceOutput).
    pub fn build(self) -> crate::operation::create_consumable_resource::CreateConsumableResourceOutput {
        crate::operation::create_consumable_resource::CreateConsumableResourceOutput {
            consumable_resource_name: self.consumable_resource_name,
            consumable_resource_arn: self.consumable_resource_arn,
            _request_id: self._request_id,
        }
    }
}

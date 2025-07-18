// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a usage plan key to identify a plan customer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetUsagePlanKeyOutput {
    /// <p>The Id of a usage plan key.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The type of a usage plan key. Currently, the valid key type is <code>API_KEY</code>.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The value of a usage plan key.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>The name of a usage plan key.</p>
    pub name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetUsagePlanKeyOutput {
    /// <p>The Id of a usage plan key.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The type of a usage plan key. Currently, the valid key type is <code>API_KEY</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The value of a usage plan key.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>The name of a usage plan key.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetUsagePlanKeyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetUsagePlanKeyOutput {
    /// Creates a new builder-style object to manufacture [`GetUsagePlanKeyOutput`](crate::operation::get_usage_plan_key::GetUsagePlanKeyOutput).
    pub fn builder() -> crate::operation::get_usage_plan_key::builders::GetUsagePlanKeyOutputBuilder {
        crate::operation::get_usage_plan_key::builders::GetUsagePlanKeyOutputBuilder::default()
    }
}

/// A builder for [`GetUsagePlanKeyOutput`](crate::operation::get_usage_plan_key::GetUsagePlanKeyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetUsagePlanKeyOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetUsagePlanKeyOutputBuilder {
    /// <p>The Id of a usage plan key.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Id of a usage plan key.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The Id of a usage plan key.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The type of a usage plan key. Currently, the valid key type is <code>API_KEY</code>.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of a usage plan key. Currently, the valid key type is <code>API_KEY</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of a usage plan key. Currently, the valid key type is <code>API_KEY</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The value of a usage plan key.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of a usage plan key.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of a usage plan key.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The name of a usage plan key.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a usage plan key.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of a usage plan key.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetUsagePlanKeyOutput`](crate::operation::get_usage_plan_key::GetUsagePlanKeyOutput).
    pub fn build(self) -> crate::operation::get_usage_plan_key::GetUsagePlanKeyOutput {
        crate::operation::get_usage_plan_key::GetUsagePlanKeyOutput {
            id: self.id,
            r#type: self.r#type,
            value: self.value,
            name: self.name,
            _request_id: self._request_id,
        }
    }
}

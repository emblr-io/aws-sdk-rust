// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output of the CreateThing operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateThingOutput {
    /// <p>The name of the new thing.</p>
    pub thing_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the new thing.</p>
    pub thing_arn: ::std::option::Option<::std::string::String>,
    /// <p>The thing ID.</p>
    pub thing_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateThingOutput {
    /// <p>The name of the new thing.</p>
    pub fn thing_name(&self) -> ::std::option::Option<&str> {
        self.thing_name.as_deref()
    }
    /// <p>The ARN of the new thing.</p>
    pub fn thing_arn(&self) -> ::std::option::Option<&str> {
        self.thing_arn.as_deref()
    }
    /// <p>The thing ID.</p>
    pub fn thing_id(&self) -> ::std::option::Option<&str> {
        self.thing_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateThingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateThingOutput {
    /// Creates a new builder-style object to manufacture [`CreateThingOutput`](crate::operation::create_thing::CreateThingOutput).
    pub fn builder() -> crate::operation::create_thing::builders::CreateThingOutputBuilder {
        crate::operation::create_thing::builders::CreateThingOutputBuilder::default()
    }
}

/// A builder for [`CreateThingOutput`](crate::operation::create_thing::CreateThingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateThingOutputBuilder {
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) thing_arn: ::std::option::Option<::std::string::String>,
    pub(crate) thing_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateThingOutputBuilder {
    /// <p>The name of the new thing.</p>
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the new thing.</p>
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// <p>The name of the new thing.</p>
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// <p>The ARN of the new thing.</p>
    pub fn thing_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the new thing.</p>
    pub fn set_thing_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_arn = input;
        self
    }
    /// <p>The ARN of the new thing.</p>
    pub fn get_thing_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_arn
    }
    /// <p>The thing ID.</p>
    pub fn thing_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The thing ID.</p>
    pub fn set_thing_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_id = input;
        self
    }
    /// <p>The thing ID.</p>
    pub fn get_thing_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateThingOutput`](crate::operation::create_thing::CreateThingOutput).
    pub fn build(self) -> crate::operation::create_thing::CreateThingOutput {
        crate::operation::create_thing::CreateThingOutput {
            thing_name: self.thing_name,
            thing_arn: self.thing_arn,
            thing_id: self.thing_id,
            _request_id: self._request_id,
        }
    }
}

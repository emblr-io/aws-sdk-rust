// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBrokerOutput {
    /// <p>The broker's Amazon Resource Name (ARN).</p>
    pub broker_arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub broker_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateBrokerOutput {
    /// <p>The broker's Amazon Resource Name (ARN).</p>
    pub fn broker_arn(&self) -> ::std::option::Option<&str> {
        self.broker_arn.as_deref()
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn broker_id(&self) -> ::std::option::Option<&str> {
        self.broker_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateBrokerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateBrokerOutput {
    /// Creates a new builder-style object to manufacture [`CreateBrokerOutput`](crate::operation::create_broker::CreateBrokerOutput).
    pub fn builder() -> crate::operation::create_broker::builders::CreateBrokerOutputBuilder {
        crate::operation::create_broker::builders::CreateBrokerOutputBuilder::default()
    }
}

/// A builder for [`CreateBrokerOutput`](crate::operation::create_broker::CreateBrokerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBrokerOutputBuilder {
    pub(crate) broker_arn: ::std::option::Option<::std::string::String>,
    pub(crate) broker_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateBrokerOutputBuilder {
    /// <p>The broker's Amazon Resource Name (ARN).</p>
    pub fn broker_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.broker_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The broker's Amazon Resource Name (ARN).</p>
    pub fn set_broker_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.broker_arn = input;
        self
    }
    /// <p>The broker's Amazon Resource Name (ARN).</p>
    pub fn get_broker_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.broker_arn
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn broker_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.broker_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn set_broker_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.broker_id = input;
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn get_broker_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.broker_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateBrokerOutput`](crate::operation::create_broker::CreateBrokerOutput).
    pub fn build(self) -> crate::operation::create_broker::CreateBrokerOutput {
        crate::operation::create_broker::CreateBrokerOutput {
            broker_arn: self.broker_arn,
            broker_id: self.broker_id,
            _request_id: self._request_id,
        }
    }
}

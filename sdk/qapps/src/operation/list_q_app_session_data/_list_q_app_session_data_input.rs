// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListQAppSessionDataInput {
    /// <p>The unique identifier of the Amazon Q Business application environment instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the Q App data collection session.</p>
    pub session_id: ::std::option::Option<::std::string::String>,
}
impl ListQAppSessionDataInput {
    /// <p>The unique identifier of the Amazon Q Business application environment instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The unique identifier of the Q App data collection session.</p>
    pub fn session_id(&self) -> ::std::option::Option<&str> {
        self.session_id.as_deref()
    }
}
impl ListQAppSessionDataInput {
    /// Creates a new builder-style object to manufacture [`ListQAppSessionDataInput`](crate::operation::list_q_app_session_data::ListQAppSessionDataInput).
    pub fn builder() -> crate::operation::list_q_app_session_data::builders::ListQAppSessionDataInputBuilder {
        crate::operation::list_q_app_session_data::builders::ListQAppSessionDataInputBuilder::default()
    }
}

/// A builder for [`ListQAppSessionDataInput`](crate::operation::list_q_app_session_data::ListQAppSessionDataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListQAppSessionDataInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
}
impl ListQAppSessionDataInputBuilder {
    /// <p>The unique identifier of the Amazon Q Business application environment instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Amazon Q Business application environment instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The unique identifier of the Amazon Q Business application environment instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The unique identifier of the Q App data collection session.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Q App data collection session.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The unique identifier of the Q App data collection session.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// Consumes the builder and constructs a [`ListQAppSessionDataInput`](crate::operation::list_q_app_session_data::ListQAppSessionDataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_q_app_session_data::ListQAppSessionDataInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_q_app_session_data::ListQAppSessionDataInput {
            instance_id: self.instance_id,
            session_id: self.session_id,
        })
    }
}

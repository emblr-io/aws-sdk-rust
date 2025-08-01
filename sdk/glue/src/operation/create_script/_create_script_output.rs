// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateScriptOutput {
    /// <p>The Python script generated from the DAG.</p>
    pub python_script: ::std::option::Option<::std::string::String>,
    /// <p>The Scala code generated from the DAG.</p>
    pub scala_code: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateScriptOutput {
    /// <p>The Python script generated from the DAG.</p>
    pub fn python_script(&self) -> ::std::option::Option<&str> {
        self.python_script.as_deref()
    }
    /// <p>The Scala code generated from the DAG.</p>
    pub fn scala_code(&self) -> ::std::option::Option<&str> {
        self.scala_code.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateScriptOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateScriptOutput {
    /// Creates a new builder-style object to manufacture [`CreateScriptOutput`](crate::operation::create_script::CreateScriptOutput).
    pub fn builder() -> crate::operation::create_script::builders::CreateScriptOutputBuilder {
        crate::operation::create_script::builders::CreateScriptOutputBuilder::default()
    }
}

/// A builder for [`CreateScriptOutput`](crate::operation::create_script::CreateScriptOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateScriptOutputBuilder {
    pub(crate) python_script: ::std::option::Option<::std::string::String>,
    pub(crate) scala_code: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateScriptOutputBuilder {
    /// <p>The Python script generated from the DAG.</p>
    pub fn python_script(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.python_script = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Python script generated from the DAG.</p>
    pub fn set_python_script(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.python_script = input;
        self
    }
    /// <p>The Python script generated from the DAG.</p>
    pub fn get_python_script(&self) -> &::std::option::Option<::std::string::String> {
        &self.python_script
    }
    /// <p>The Scala code generated from the DAG.</p>
    pub fn scala_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scala_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Scala code generated from the DAG.</p>
    pub fn set_scala_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scala_code = input;
        self
    }
    /// <p>The Scala code generated from the DAG.</p>
    pub fn get_scala_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.scala_code
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateScriptOutput`](crate::operation::create_script::CreateScriptOutput).
    pub fn build(self) -> crate::operation::create_script::CreateScriptOutput {
        crate::operation::create_script::CreateScriptOutput {
            python_script: self.python_script,
            scala_code: self.scala_code,
            _request_id: self._request_id,
        }
    }
}

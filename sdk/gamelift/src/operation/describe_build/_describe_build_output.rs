// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeBuildOutput {
    /// <p>Set of properties describing the requested build.</p>
    ///
    /// _Note: This member has been renamed from `build`._
    pub build_value: ::std::option::Option<crate::types::Build>,
    _request_id: Option<String>,
}
impl DescribeBuildOutput {
    /// <p>Set of properties describing the requested build.</p>
    ///
    /// _Note: This member has been renamed from `build`._
    pub fn build_value(&self) -> ::std::option::Option<&crate::types::Build> {
        self.build_value.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeBuildOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeBuildOutput {
    /// Creates a new builder-style object to manufacture [`DescribeBuildOutput`](crate::operation::describe_build::DescribeBuildOutput).
    pub fn builder() -> crate::operation::describe_build::builders::DescribeBuildOutputBuilder {
        crate::operation::describe_build::builders::DescribeBuildOutputBuilder::default()
    }
}

/// A builder for [`DescribeBuildOutput`](crate::operation::describe_build::DescribeBuildOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeBuildOutputBuilder {
    pub(crate) build_value: ::std::option::Option<crate::types::Build>,
    _request_id: Option<String>,
}
impl DescribeBuildOutputBuilder {
    /// <p>Set of properties describing the requested build.</p>
    pub fn build_value(mut self, input: crate::types::Build) -> Self {
        self.build_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set of properties describing the requested build.</p>
    pub fn set_build(mut self, input: ::std::option::Option<crate::types::Build>) -> Self {
        self.build_value = input;
        self
    }
    /// <p>Set of properties describing the requested build.</p>
    pub fn get_build(&self) -> &::std::option::Option<crate::types::Build> {
        &self.build_value
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeBuildOutput`](crate::operation::describe_build::DescribeBuildOutput).
    pub fn build(self) -> crate::operation::describe_build::DescribeBuildOutput {
        crate::operation::describe_build::DescribeBuildOutput {
            build_value: self.build_value,
            _request_id: self._request_id,
        }
    }
}

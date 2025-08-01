// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for UpdateMultiplexProgramResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateMultiplexProgramOutput {
    /// The updated multiplex program.
    pub multiplex_program: ::std::option::Option<crate::types::MultiplexProgram>,
    _request_id: Option<String>,
}
impl UpdateMultiplexProgramOutput {
    /// The updated multiplex program.
    pub fn multiplex_program(&self) -> ::std::option::Option<&crate::types::MultiplexProgram> {
        self.multiplex_program.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateMultiplexProgramOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateMultiplexProgramOutput {
    /// Creates a new builder-style object to manufacture [`UpdateMultiplexProgramOutput`](crate::operation::update_multiplex_program::UpdateMultiplexProgramOutput).
    pub fn builder() -> crate::operation::update_multiplex_program::builders::UpdateMultiplexProgramOutputBuilder {
        crate::operation::update_multiplex_program::builders::UpdateMultiplexProgramOutputBuilder::default()
    }
}

/// A builder for [`UpdateMultiplexProgramOutput`](crate::operation::update_multiplex_program::UpdateMultiplexProgramOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateMultiplexProgramOutputBuilder {
    pub(crate) multiplex_program: ::std::option::Option<crate::types::MultiplexProgram>,
    _request_id: Option<String>,
}
impl UpdateMultiplexProgramOutputBuilder {
    /// The updated multiplex program.
    pub fn multiplex_program(mut self, input: crate::types::MultiplexProgram) -> Self {
        self.multiplex_program = ::std::option::Option::Some(input);
        self
    }
    /// The updated multiplex program.
    pub fn set_multiplex_program(mut self, input: ::std::option::Option<crate::types::MultiplexProgram>) -> Self {
        self.multiplex_program = input;
        self
    }
    /// The updated multiplex program.
    pub fn get_multiplex_program(&self) -> &::std::option::Option<crate::types::MultiplexProgram> {
        &self.multiplex_program
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateMultiplexProgramOutput`](crate::operation::update_multiplex_program::UpdateMultiplexProgramOutput).
    pub fn build(self) -> crate::operation::update_multiplex_program::UpdateMultiplexProgramOutput {
        crate::operation::update_multiplex_program::UpdateMultiplexProgramOutput {
            multiplex_program: self.multiplex_program,
            _request_id: self._request_id,
        }
    }
}

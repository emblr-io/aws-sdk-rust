// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTrafficMirrorSessionInput {
    /// <p>The ID of the Traffic Mirror session.</p>
    pub traffic_mirror_session_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DeleteTrafficMirrorSessionInput {
    /// <p>The ID of the Traffic Mirror session.</p>
    pub fn traffic_mirror_session_id(&self) -> ::std::option::Option<&str> {
        self.traffic_mirror_session_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DeleteTrafficMirrorSessionInput {
    /// Creates a new builder-style object to manufacture [`DeleteTrafficMirrorSessionInput`](crate::operation::delete_traffic_mirror_session::DeleteTrafficMirrorSessionInput).
    pub fn builder() -> crate::operation::delete_traffic_mirror_session::builders::DeleteTrafficMirrorSessionInputBuilder {
        crate::operation::delete_traffic_mirror_session::builders::DeleteTrafficMirrorSessionInputBuilder::default()
    }
}

/// A builder for [`DeleteTrafficMirrorSessionInput`](crate::operation::delete_traffic_mirror_session::DeleteTrafficMirrorSessionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTrafficMirrorSessionInputBuilder {
    pub(crate) traffic_mirror_session_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DeleteTrafficMirrorSessionInputBuilder {
    /// <p>The ID of the Traffic Mirror session.</p>
    /// This field is required.
    pub fn traffic_mirror_session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.traffic_mirror_session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Traffic Mirror session.</p>
    pub fn set_traffic_mirror_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.traffic_mirror_session_id = input;
        self
    }
    /// <p>The ID of the Traffic Mirror session.</p>
    pub fn get_traffic_mirror_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.traffic_mirror_session_id
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`DeleteTrafficMirrorSessionInput`](crate::operation::delete_traffic_mirror_session::DeleteTrafficMirrorSessionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_traffic_mirror_session::DeleteTrafficMirrorSessionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_traffic_mirror_session::DeleteTrafficMirrorSessionInput {
            traffic_mirror_session_id: self.traffic_mirror_session_id,
            dry_run: self.dry_run,
        })
    }
}

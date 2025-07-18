// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>This is <b>AWS WAF Classic</b> documentation. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html">AWS WAF Classic</a> in the developer guide.</p>
/// <p><b>For the latest version of AWS WAF</b>, use the AWS WAFV2 API and see the <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html">AWS WAF Developer Guide</a>. With the latest version, AWS WAF has a single set of endpoints for regional and global use.</p>
/// </note>
/// <p>Specifies the part of a web request that you want to inspect for cross-site scripting attacks and indicates whether you want to add the specification to an <code>XssMatchSet</code> or delete it from an <code>XssMatchSet</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct XssMatchSetUpdate {
    /// <p>Specify <code>INSERT</code> to add an <code>XssMatchSetUpdate</code> to an <code>XssMatchSet</code>. Use <code>DELETE</code> to remove an <code>XssMatchSetUpdate</code> from an <code>XssMatchSet</code>.</p>
    pub action: crate::types::ChangeAction,
    /// <p>Specifies the part of a web request that you want AWS WAF to inspect for cross-site scripting attacks and, if you want AWS WAF to inspect a header, the name of the header.</p>
    pub xss_match_tuple: ::std::option::Option<crate::types::XssMatchTuple>,
}
impl XssMatchSetUpdate {
    /// <p>Specify <code>INSERT</code> to add an <code>XssMatchSetUpdate</code> to an <code>XssMatchSet</code>. Use <code>DELETE</code> to remove an <code>XssMatchSetUpdate</code> from an <code>XssMatchSet</code>.</p>
    pub fn action(&self) -> &crate::types::ChangeAction {
        &self.action
    }
    /// <p>Specifies the part of a web request that you want AWS WAF to inspect for cross-site scripting attacks and, if you want AWS WAF to inspect a header, the name of the header.</p>
    pub fn xss_match_tuple(&self) -> ::std::option::Option<&crate::types::XssMatchTuple> {
        self.xss_match_tuple.as_ref()
    }
}
impl XssMatchSetUpdate {
    /// Creates a new builder-style object to manufacture [`XssMatchSetUpdate`](crate::types::XssMatchSetUpdate).
    pub fn builder() -> crate::types::builders::XssMatchSetUpdateBuilder {
        crate::types::builders::XssMatchSetUpdateBuilder::default()
    }
}

/// A builder for [`XssMatchSetUpdate`](crate::types::XssMatchSetUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct XssMatchSetUpdateBuilder {
    pub(crate) action: ::std::option::Option<crate::types::ChangeAction>,
    pub(crate) xss_match_tuple: ::std::option::Option<crate::types::XssMatchTuple>,
}
impl XssMatchSetUpdateBuilder {
    /// <p>Specify <code>INSERT</code> to add an <code>XssMatchSetUpdate</code> to an <code>XssMatchSet</code>. Use <code>DELETE</code> to remove an <code>XssMatchSetUpdate</code> from an <code>XssMatchSet</code>.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::ChangeAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify <code>INSERT</code> to add an <code>XssMatchSetUpdate</code> to an <code>XssMatchSet</code>. Use <code>DELETE</code> to remove an <code>XssMatchSetUpdate</code> from an <code>XssMatchSet</code>.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::ChangeAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>Specify <code>INSERT</code> to add an <code>XssMatchSetUpdate</code> to an <code>XssMatchSet</code>. Use <code>DELETE</code> to remove an <code>XssMatchSetUpdate</code> from an <code>XssMatchSet</code>.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::ChangeAction> {
        &self.action
    }
    /// <p>Specifies the part of a web request that you want AWS WAF to inspect for cross-site scripting attacks and, if you want AWS WAF to inspect a header, the name of the header.</p>
    /// This field is required.
    pub fn xss_match_tuple(mut self, input: crate::types::XssMatchTuple) -> Self {
        self.xss_match_tuple = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the part of a web request that you want AWS WAF to inspect for cross-site scripting attacks and, if you want AWS WAF to inspect a header, the name of the header.</p>
    pub fn set_xss_match_tuple(mut self, input: ::std::option::Option<crate::types::XssMatchTuple>) -> Self {
        self.xss_match_tuple = input;
        self
    }
    /// <p>Specifies the part of a web request that you want AWS WAF to inspect for cross-site scripting attacks and, if you want AWS WAF to inspect a header, the name of the header.</p>
    pub fn get_xss_match_tuple(&self) -> &::std::option::Option<crate::types::XssMatchTuple> {
        &self.xss_match_tuple
    }
    /// Consumes the builder and constructs a [`XssMatchSetUpdate`](crate::types::XssMatchSetUpdate).
    /// This method will fail if any of the following fields are not set:
    /// - [`action`](crate::types::builders::XssMatchSetUpdateBuilder::action)
    pub fn build(self) -> ::std::result::Result<crate::types::XssMatchSetUpdate, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::XssMatchSetUpdate {
            action: self.action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action",
                    "action was not specified but it is required when building XssMatchSetUpdate",
                )
            })?,
            xss_match_tuple: self.xss_match_tuple,
        })
    }
}

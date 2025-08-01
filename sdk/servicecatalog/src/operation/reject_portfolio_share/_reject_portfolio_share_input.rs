// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RejectPortfolioShareInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
    /// <p>The portfolio identifier.</p>
    pub portfolio_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of shared portfolios to reject. The default is to reject imported portfolios.</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_ORGANIZATIONS</code> - Reject portfolios shared by the management account of your organization.</p></li>
    /// <li>
    /// <p><code>IMPORTED</code> - Reject imported portfolios.</p></li>
    /// <li>
    /// <p><code>AWS_SERVICECATALOG</code> - Not supported. (Throws ResourceNotFoundException.)</p></li>
    /// </ul>
    /// <p>For example, <code>aws servicecatalog reject-portfolio-share --portfolio-id "port-2qwzkwxt3y5fk" --portfolio-share-type AWS_ORGANIZATIONS</code></p>
    pub portfolio_share_type: ::std::option::Option<crate::types::PortfolioShareType>,
}
impl RejectPortfolioShareInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(&self) -> ::std::option::Option<&str> {
        self.accept_language.as_deref()
    }
    /// <p>The portfolio identifier.</p>
    pub fn portfolio_id(&self) -> ::std::option::Option<&str> {
        self.portfolio_id.as_deref()
    }
    /// <p>The type of shared portfolios to reject. The default is to reject imported portfolios.</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_ORGANIZATIONS</code> - Reject portfolios shared by the management account of your organization.</p></li>
    /// <li>
    /// <p><code>IMPORTED</code> - Reject imported portfolios.</p></li>
    /// <li>
    /// <p><code>AWS_SERVICECATALOG</code> - Not supported. (Throws ResourceNotFoundException.)</p></li>
    /// </ul>
    /// <p>For example, <code>aws servicecatalog reject-portfolio-share --portfolio-id "port-2qwzkwxt3y5fk" --portfolio-share-type AWS_ORGANIZATIONS</code></p>
    pub fn portfolio_share_type(&self) -> ::std::option::Option<&crate::types::PortfolioShareType> {
        self.portfolio_share_type.as_ref()
    }
}
impl RejectPortfolioShareInput {
    /// Creates a new builder-style object to manufacture [`RejectPortfolioShareInput`](crate::operation::reject_portfolio_share::RejectPortfolioShareInput).
    pub fn builder() -> crate::operation::reject_portfolio_share::builders::RejectPortfolioShareInputBuilder {
        crate::operation::reject_portfolio_share::builders::RejectPortfolioShareInputBuilder::default()
    }
}

/// A builder for [`RejectPortfolioShareInput`](crate::operation::reject_portfolio_share::RejectPortfolioShareInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RejectPortfolioShareInputBuilder {
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
    pub(crate) portfolio_id: ::std::option::Option<::std::string::String>,
    pub(crate) portfolio_share_type: ::std::option::Option<crate::types::PortfolioShareType>,
}
impl RejectPortfolioShareInputBuilder {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accept_language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn set_accept_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accept_language = input;
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn get_accept_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.accept_language
    }
    /// <p>The portfolio identifier.</p>
    /// This field is required.
    pub fn portfolio_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.portfolio_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The portfolio identifier.</p>
    pub fn set_portfolio_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.portfolio_id = input;
        self
    }
    /// <p>The portfolio identifier.</p>
    pub fn get_portfolio_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.portfolio_id
    }
    /// <p>The type of shared portfolios to reject. The default is to reject imported portfolios.</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_ORGANIZATIONS</code> - Reject portfolios shared by the management account of your organization.</p></li>
    /// <li>
    /// <p><code>IMPORTED</code> - Reject imported portfolios.</p></li>
    /// <li>
    /// <p><code>AWS_SERVICECATALOG</code> - Not supported. (Throws ResourceNotFoundException.)</p></li>
    /// </ul>
    /// <p>For example, <code>aws servicecatalog reject-portfolio-share --portfolio-id "port-2qwzkwxt3y5fk" --portfolio-share-type AWS_ORGANIZATIONS</code></p>
    pub fn portfolio_share_type(mut self, input: crate::types::PortfolioShareType) -> Self {
        self.portfolio_share_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of shared portfolios to reject. The default is to reject imported portfolios.</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_ORGANIZATIONS</code> - Reject portfolios shared by the management account of your organization.</p></li>
    /// <li>
    /// <p><code>IMPORTED</code> - Reject imported portfolios.</p></li>
    /// <li>
    /// <p><code>AWS_SERVICECATALOG</code> - Not supported. (Throws ResourceNotFoundException.)</p></li>
    /// </ul>
    /// <p>For example, <code>aws servicecatalog reject-portfolio-share --portfolio-id "port-2qwzkwxt3y5fk" --portfolio-share-type AWS_ORGANIZATIONS</code></p>
    pub fn set_portfolio_share_type(mut self, input: ::std::option::Option<crate::types::PortfolioShareType>) -> Self {
        self.portfolio_share_type = input;
        self
    }
    /// <p>The type of shared portfolios to reject. The default is to reject imported portfolios.</p>
    /// <ul>
    /// <li>
    /// <p><code>AWS_ORGANIZATIONS</code> - Reject portfolios shared by the management account of your organization.</p></li>
    /// <li>
    /// <p><code>IMPORTED</code> - Reject imported portfolios.</p></li>
    /// <li>
    /// <p><code>AWS_SERVICECATALOG</code> - Not supported. (Throws ResourceNotFoundException.)</p></li>
    /// </ul>
    /// <p>For example, <code>aws servicecatalog reject-portfolio-share --portfolio-id "port-2qwzkwxt3y5fk" --portfolio-share-type AWS_ORGANIZATIONS</code></p>
    pub fn get_portfolio_share_type(&self) -> &::std::option::Option<crate::types::PortfolioShareType> {
        &self.portfolio_share_type
    }
    /// Consumes the builder and constructs a [`RejectPortfolioShareInput`](crate::operation::reject_portfolio_share::RejectPortfolioShareInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::reject_portfolio_share::RejectPortfolioShareInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::reject_portfolio_share::RejectPortfolioShareInput {
            accept_language: self.accept_language,
            portfolio_id: self.portfolio_id,
            portfolio_share_type: self.portfolio_share_type,
        })
    }
}

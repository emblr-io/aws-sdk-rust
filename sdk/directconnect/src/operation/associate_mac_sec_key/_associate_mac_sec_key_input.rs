// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateMacSecKeyInput {
    /// <p>The ID of the dedicated connection (dxcon-xxxx), or the ID of the LAG (dxlag-xxxx).</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve connection ID.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the MAC Security (MACsec) secret key to associate with the dedicated connection.</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve the MAC Security (MACsec) secret key.</p>
    /// <p>If you use this request parameter, you do not use the <code>ckn</code> and <code>cak</code> request parameters.</p>
    pub secret_arn: ::std::option::Option<::std::string::String>,
    /// <p>The MAC Security (MACsec) CKN to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>cak</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub ckn: ::std::option::Option<::std::string::String>,
    /// <p>The MAC Security (MACsec) CAK to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>ckn</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub cak: ::std::option::Option<::std::string::String>,
}
impl AssociateMacSecKeyInput {
    /// <p>The ID of the dedicated connection (dxcon-xxxx), or the ID of the LAG (dxlag-xxxx).</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve connection ID.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the MAC Security (MACsec) secret key to associate with the dedicated connection.</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve the MAC Security (MACsec) secret key.</p>
    /// <p>If you use this request parameter, you do not use the <code>ckn</code> and <code>cak</code> request parameters.</p>
    pub fn secret_arn(&self) -> ::std::option::Option<&str> {
        self.secret_arn.as_deref()
    }
    /// <p>The MAC Security (MACsec) CKN to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>cak</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn ckn(&self) -> ::std::option::Option<&str> {
        self.ckn.as_deref()
    }
    /// <p>The MAC Security (MACsec) CAK to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>ckn</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn cak(&self) -> ::std::option::Option<&str> {
        self.cak.as_deref()
    }
}
impl AssociateMacSecKeyInput {
    /// Creates a new builder-style object to manufacture [`AssociateMacSecKeyInput`](crate::operation::associate_mac_sec_key::AssociateMacSecKeyInput).
    pub fn builder() -> crate::operation::associate_mac_sec_key::builders::AssociateMacSecKeyInputBuilder {
        crate::operation::associate_mac_sec_key::builders::AssociateMacSecKeyInputBuilder::default()
    }
}

/// A builder for [`AssociateMacSecKeyInput`](crate::operation::associate_mac_sec_key::AssociateMacSecKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateMacSecKeyInputBuilder {
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
    pub(crate) secret_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ckn: ::std::option::Option<::std::string::String>,
    pub(crate) cak: ::std::option::Option<::std::string::String>,
}
impl AssociateMacSecKeyInputBuilder {
    /// <p>The ID of the dedicated connection (dxcon-xxxx), or the ID of the LAG (dxlag-xxxx).</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve connection ID.</p>
    /// This field is required.
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the dedicated connection (dxcon-xxxx), or the ID of the LAG (dxlag-xxxx).</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve connection ID.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The ID of the dedicated connection (dxcon-xxxx), or the ID of the LAG (dxlag-xxxx).</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve connection ID.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// <p>The Amazon Resource Name (ARN) of the MAC Security (MACsec) secret key to associate with the dedicated connection.</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve the MAC Security (MACsec) secret key.</p>
    /// <p>If you use this request parameter, you do not use the <code>ckn</code> and <code>cak</code> request parameters.</p>
    pub fn secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the MAC Security (MACsec) secret key to associate with the dedicated connection.</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve the MAC Security (MACsec) secret key.</p>
    /// <p>If you use this request parameter, you do not use the <code>ckn</code> and <code>cak</code> request parameters.</p>
    pub fn set_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the MAC Security (MACsec) secret key to associate with the dedicated connection.</p>
    /// <p>You can use <code>DescribeConnections</code> or <code>DescribeLags</code> to retrieve the MAC Security (MACsec) secret key.</p>
    /// <p>If you use this request parameter, you do not use the <code>ckn</code> and <code>cak</code> request parameters.</p>
    pub fn get_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_arn
    }
    /// <p>The MAC Security (MACsec) CKN to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>cak</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn ckn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ckn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The MAC Security (MACsec) CKN to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>cak</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn set_ckn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ckn = input;
        self
    }
    /// <p>The MAC Security (MACsec) CKN to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>cak</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn get_ckn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ckn
    }
    /// <p>The MAC Security (MACsec) CAK to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>ckn</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn cak(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cak = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The MAC Security (MACsec) CAK to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>ckn</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn set_cak(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cak = input;
        self
    }
    /// <p>The MAC Security (MACsec) CAK to associate with the dedicated connection.</p>
    /// <p>You can create the CKN/CAK pair using an industry standard tool.</p>
    /// <p>The valid values are 64 hexadecimal characters (0-9, A-E).</p>
    /// <p>If you use this request parameter, you must use the <code>ckn</code> request parameter and not use the <code>secretARN</code> request parameter.</p>
    pub fn get_cak(&self) -> &::std::option::Option<::std::string::String> {
        &self.cak
    }
    /// Consumes the builder and constructs a [`AssociateMacSecKeyInput`](crate::operation::associate_mac_sec_key::AssociateMacSecKeyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::associate_mac_sec_key::AssociateMacSecKeyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::associate_mac_sec_key::AssociateMacSecKeyInput {
            connection_id: self.connection_id,
            secret_arn: self.secret_arn,
            ckn: self.ckn,
            cak: self.cak,
        })
    }
}

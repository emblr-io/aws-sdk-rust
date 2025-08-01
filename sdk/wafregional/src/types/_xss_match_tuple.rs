// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>This is <b>AWS WAF Classic</b> documentation. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html">AWS WAF Classic</a> in the developer guide.</p>
/// <p><b>For the latest version of AWS WAF</b>, use the AWS WAFV2 API and see the <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html">AWS WAF Developer Guide</a>. With the latest version, AWS WAF has a single set of endpoints for regional and global use.</p>
/// </note>
/// <p>Specifies the part of a web request that you want AWS WAF to inspect for cross-site scripting attacks and, if you want AWS WAF to inspect a header, the name of the header.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct XssMatchTuple {
    /// <p>Specifies where in a web request to look for cross-site scripting attacks.</p>
    pub field_to_match: ::std::option::Option<crate::types::FieldToMatch>,
    /// <p>Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass AWS WAF. If you specify a transformation, AWS WAF performs the transformation on <code>FieldToMatch</code> before inspecting it for a match.</p>
    /// <p>You can only specify a single type of TextTransformation.</p>
    /// <p><b>CMD_LINE</b></p>
    /// <p>When you're concerned that attackers are injecting an operating system command line command and using unusual formatting to disguise some or all of the command, use this option to perform the following transformations:</p>
    /// <ul>
    /// <li>
    /// <p>Delete the following characters: \ " ' ^</p></li>
    /// <li>
    /// <p>Delete spaces before the following characters: / (</p></li>
    /// <li>
    /// <p>Replace the following characters with a space: , ;</p></li>
    /// <li>
    /// <p>Replace multiple spaces with one space</p></li>
    /// <li>
    /// <p>Convert uppercase letters (A-Z) to lowercase (a-z)</p></li>
    /// </ul>
    /// <p><b>COMPRESS_WHITE_SPACE</b></p>
    /// <p>Use this option to replace the following characters with a space character (decimal 32):</p>
    /// <ul>
    /// <li>
    /// <p>\f, formfeed, decimal 12</p></li>
    /// <li>
    /// <p>\t, tab, decimal 9</p></li>
    /// <li>
    /// <p>\n, newline, decimal 10</p></li>
    /// <li>
    /// <p>\r, carriage return, decimal 13</p></li>
    /// <li>
    /// <p>\v, vertical tab, decimal 11</p></li>
    /// <li>
    /// <p>non-breaking space, decimal 160</p></li>
    /// </ul>
    /// <p><code>COMPRESS_WHITE_SPACE</code> also replaces multiple spaces with one space.</p>
    /// <p><b>HTML_ENTITY_DECODE</b></p>
    /// <p>Use this option to replace HTML-encoded characters with unencoded characters. <code>HTML_ENTITY_DECODE</code> performs the following operations:</p>
    /// <ul>
    /// <li>
    /// <p>Replaces <code>(ampersand)quot;</code> with <code>"</code></p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)nbsp;</code> with a non-breaking space, decimal 160</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)lt;</code> with a "less than" symbol</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)gt;</code> with <code>&gt;</code></p></li>
    /// <li>
    /// <p>Replaces characters that are represented in hexadecimal format, <code>(ampersand)#xhhhh;</code>, with the corresponding characters</p></li>
    /// <li>
    /// <p>Replaces characters that are represented in decimal format, <code>(ampersand)#nnnn;</code>, with the corresponding characters</p></li>
    /// </ul>
    /// <p><b>LOWERCASE</b></p>
    /// <p>Use this option to convert uppercase letters (A-Z) to lowercase (a-z).</p>
    /// <p><b>URL_DECODE</b></p>
    /// <p>Use this option to decode a URL-encoded value.</p>
    /// <p><b>NONE</b></p>
    /// <p>Specify <code>NONE</code> if you don't want to perform any text transformations.</p>
    pub text_transformation: crate::types::TextTransformation,
}
impl XssMatchTuple {
    /// <p>Specifies where in a web request to look for cross-site scripting attacks.</p>
    pub fn field_to_match(&self) -> ::std::option::Option<&crate::types::FieldToMatch> {
        self.field_to_match.as_ref()
    }
    /// <p>Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass AWS WAF. If you specify a transformation, AWS WAF performs the transformation on <code>FieldToMatch</code> before inspecting it for a match.</p>
    /// <p>You can only specify a single type of TextTransformation.</p>
    /// <p><b>CMD_LINE</b></p>
    /// <p>When you're concerned that attackers are injecting an operating system command line command and using unusual formatting to disguise some or all of the command, use this option to perform the following transformations:</p>
    /// <ul>
    /// <li>
    /// <p>Delete the following characters: \ " ' ^</p></li>
    /// <li>
    /// <p>Delete spaces before the following characters: / (</p></li>
    /// <li>
    /// <p>Replace the following characters with a space: , ;</p></li>
    /// <li>
    /// <p>Replace multiple spaces with one space</p></li>
    /// <li>
    /// <p>Convert uppercase letters (A-Z) to lowercase (a-z)</p></li>
    /// </ul>
    /// <p><b>COMPRESS_WHITE_SPACE</b></p>
    /// <p>Use this option to replace the following characters with a space character (decimal 32):</p>
    /// <ul>
    /// <li>
    /// <p>\f, formfeed, decimal 12</p></li>
    /// <li>
    /// <p>\t, tab, decimal 9</p></li>
    /// <li>
    /// <p>\n, newline, decimal 10</p></li>
    /// <li>
    /// <p>\r, carriage return, decimal 13</p></li>
    /// <li>
    /// <p>\v, vertical tab, decimal 11</p></li>
    /// <li>
    /// <p>non-breaking space, decimal 160</p></li>
    /// </ul>
    /// <p><code>COMPRESS_WHITE_SPACE</code> also replaces multiple spaces with one space.</p>
    /// <p><b>HTML_ENTITY_DECODE</b></p>
    /// <p>Use this option to replace HTML-encoded characters with unencoded characters. <code>HTML_ENTITY_DECODE</code> performs the following operations:</p>
    /// <ul>
    /// <li>
    /// <p>Replaces <code>(ampersand)quot;</code> with <code>"</code></p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)nbsp;</code> with a non-breaking space, decimal 160</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)lt;</code> with a "less than" symbol</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)gt;</code> with <code>&gt;</code></p></li>
    /// <li>
    /// <p>Replaces characters that are represented in hexadecimal format, <code>(ampersand)#xhhhh;</code>, with the corresponding characters</p></li>
    /// <li>
    /// <p>Replaces characters that are represented in decimal format, <code>(ampersand)#nnnn;</code>, with the corresponding characters</p></li>
    /// </ul>
    /// <p><b>LOWERCASE</b></p>
    /// <p>Use this option to convert uppercase letters (A-Z) to lowercase (a-z).</p>
    /// <p><b>URL_DECODE</b></p>
    /// <p>Use this option to decode a URL-encoded value.</p>
    /// <p><b>NONE</b></p>
    /// <p>Specify <code>NONE</code> if you don't want to perform any text transformations.</p>
    pub fn text_transformation(&self) -> &crate::types::TextTransformation {
        &self.text_transformation
    }
}
impl XssMatchTuple {
    /// Creates a new builder-style object to manufacture [`XssMatchTuple`](crate::types::XssMatchTuple).
    pub fn builder() -> crate::types::builders::XssMatchTupleBuilder {
        crate::types::builders::XssMatchTupleBuilder::default()
    }
}

/// A builder for [`XssMatchTuple`](crate::types::XssMatchTuple).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct XssMatchTupleBuilder {
    pub(crate) field_to_match: ::std::option::Option<crate::types::FieldToMatch>,
    pub(crate) text_transformation: ::std::option::Option<crate::types::TextTransformation>,
}
impl XssMatchTupleBuilder {
    /// <p>Specifies where in a web request to look for cross-site scripting attacks.</p>
    /// This field is required.
    pub fn field_to_match(mut self, input: crate::types::FieldToMatch) -> Self {
        self.field_to_match = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies where in a web request to look for cross-site scripting attacks.</p>
    pub fn set_field_to_match(mut self, input: ::std::option::Option<crate::types::FieldToMatch>) -> Self {
        self.field_to_match = input;
        self
    }
    /// <p>Specifies where in a web request to look for cross-site scripting attacks.</p>
    pub fn get_field_to_match(&self) -> &::std::option::Option<crate::types::FieldToMatch> {
        &self.field_to_match
    }
    /// <p>Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass AWS WAF. If you specify a transformation, AWS WAF performs the transformation on <code>FieldToMatch</code> before inspecting it for a match.</p>
    /// <p>You can only specify a single type of TextTransformation.</p>
    /// <p><b>CMD_LINE</b></p>
    /// <p>When you're concerned that attackers are injecting an operating system command line command and using unusual formatting to disguise some or all of the command, use this option to perform the following transformations:</p>
    /// <ul>
    /// <li>
    /// <p>Delete the following characters: \ " ' ^</p></li>
    /// <li>
    /// <p>Delete spaces before the following characters: / (</p></li>
    /// <li>
    /// <p>Replace the following characters with a space: , ;</p></li>
    /// <li>
    /// <p>Replace multiple spaces with one space</p></li>
    /// <li>
    /// <p>Convert uppercase letters (A-Z) to lowercase (a-z)</p></li>
    /// </ul>
    /// <p><b>COMPRESS_WHITE_SPACE</b></p>
    /// <p>Use this option to replace the following characters with a space character (decimal 32):</p>
    /// <ul>
    /// <li>
    /// <p>\f, formfeed, decimal 12</p></li>
    /// <li>
    /// <p>\t, tab, decimal 9</p></li>
    /// <li>
    /// <p>\n, newline, decimal 10</p></li>
    /// <li>
    /// <p>\r, carriage return, decimal 13</p></li>
    /// <li>
    /// <p>\v, vertical tab, decimal 11</p></li>
    /// <li>
    /// <p>non-breaking space, decimal 160</p></li>
    /// </ul>
    /// <p><code>COMPRESS_WHITE_SPACE</code> also replaces multiple spaces with one space.</p>
    /// <p><b>HTML_ENTITY_DECODE</b></p>
    /// <p>Use this option to replace HTML-encoded characters with unencoded characters. <code>HTML_ENTITY_DECODE</code> performs the following operations:</p>
    /// <ul>
    /// <li>
    /// <p>Replaces <code>(ampersand)quot;</code> with <code>"</code></p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)nbsp;</code> with a non-breaking space, decimal 160</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)lt;</code> with a "less than" symbol</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)gt;</code> with <code>&gt;</code></p></li>
    /// <li>
    /// <p>Replaces characters that are represented in hexadecimal format, <code>(ampersand)#xhhhh;</code>, with the corresponding characters</p></li>
    /// <li>
    /// <p>Replaces characters that are represented in decimal format, <code>(ampersand)#nnnn;</code>, with the corresponding characters</p></li>
    /// </ul>
    /// <p><b>LOWERCASE</b></p>
    /// <p>Use this option to convert uppercase letters (A-Z) to lowercase (a-z).</p>
    /// <p><b>URL_DECODE</b></p>
    /// <p>Use this option to decode a URL-encoded value.</p>
    /// <p><b>NONE</b></p>
    /// <p>Specify <code>NONE</code> if you don't want to perform any text transformations.</p>
    /// This field is required.
    pub fn text_transformation(mut self, input: crate::types::TextTransformation) -> Self {
        self.text_transformation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass AWS WAF. If you specify a transformation, AWS WAF performs the transformation on <code>FieldToMatch</code> before inspecting it for a match.</p>
    /// <p>You can only specify a single type of TextTransformation.</p>
    /// <p><b>CMD_LINE</b></p>
    /// <p>When you're concerned that attackers are injecting an operating system command line command and using unusual formatting to disguise some or all of the command, use this option to perform the following transformations:</p>
    /// <ul>
    /// <li>
    /// <p>Delete the following characters: \ " ' ^</p></li>
    /// <li>
    /// <p>Delete spaces before the following characters: / (</p></li>
    /// <li>
    /// <p>Replace the following characters with a space: , ;</p></li>
    /// <li>
    /// <p>Replace multiple spaces with one space</p></li>
    /// <li>
    /// <p>Convert uppercase letters (A-Z) to lowercase (a-z)</p></li>
    /// </ul>
    /// <p><b>COMPRESS_WHITE_SPACE</b></p>
    /// <p>Use this option to replace the following characters with a space character (decimal 32):</p>
    /// <ul>
    /// <li>
    /// <p>\f, formfeed, decimal 12</p></li>
    /// <li>
    /// <p>\t, tab, decimal 9</p></li>
    /// <li>
    /// <p>\n, newline, decimal 10</p></li>
    /// <li>
    /// <p>\r, carriage return, decimal 13</p></li>
    /// <li>
    /// <p>\v, vertical tab, decimal 11</p></li>
    /// <li>
    /// <p>non-breaking space, decimal 160</p></li>
    /// </ul>
    /// <p><code>COMPRESS_WHITE_SPACE</code> also replaces multiple spaces with one space.</p>
    /// <p><b>HTML_ENTITY_DECODE</b></p>
    /// <p>Use this option to replace HTML-encoded characters with unencoded characters. <code>HTML_ENTITY_DECODE</code> performs the following operations:</p>
    /// <ul>
    /// <li>
    /// <p>Replaces <code>(ampersand)quot;</code> with <code>"</code></p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)nbsp;</code> with a non-breaking space, decimal 160</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)lt;</code> with a "less than" symbol</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)gt;</code> with <code>&gt;</code></p></li>
    /// <li>
    /// <p>Replaces characters that are represented in hexadecimal format, <code>(ampersand)#xhhhh;</code>, with the corresponding characters</p></li>
    /// <li>
    /// <p>Replaces characters that are represented in decimal format, <code>(ampersand)#nnnn;</code>, with the corresponding characters</p></li>
    /// </ul>
    /// <p><b>LOWERCASE</b></p>
    /// <p>Use this option to convert uppercase letters (A-Z) to lowercase (a-z).</p>
    /// <p><b>URL_DECODE</b></p>
    /// <p>Use this option to decode a URL-encoded value.</p>
    /// <p><b>NONE</b></p>
    /// <p>Specify <code>NONE</code> if you don't want to perform any text transformations.</p>
    pub fn set_text_transformation(mut self, input: ::std::option::Option<crate::types::TextTransformation>) -> Self {
        self.text_transformation = input;
        self
    }
    /// <p>Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass AWS WAF. If you specify a transformation, AWS WAF performs the transformation on <code>FieldToMatch</code> before inspecting it for a match.</p>
    /// <p>You can only specify a single type of TextTransformation.</p>
    /// <p><b>CMD_LINE</b></p>
    /// <p>When you're concerned that attackers are injecting an operating system command line command and using unusual formatting to disguise some or all of the command, use this option to perform the following transformations:</p>
    /// <ul>
    /// <li>
    /// <p>Delete the following characters: \ " ' ^</p></li>
    /// <li>
    /// <p>Delete spaces before the following characters: / (</p></li>
    /// <li>
    /// <p>Replace the following characters with a space: , ;</p></li>
    /// <li>
    /// <p>Replace multiple spaces with one space</p></li>
    /// <li>
    /// <p>Convert uppercase letters (A-Z) to lowercase (a-z)</p></li>
    /// </ul>
    /// <p><b>COMPRESS_WHITE_SPACE</b></p>
    /// <p>Use this option to replace the following characters with a space character (decimal 32):</p>
    /// <ul>
    /// <li>
    /// <p>\f, formfeed, decimal 12</p></li>
    /// <li>
    /// <p>\t, tab, decimal 9</p></li>
    /// <li>
    /// <p>\n, newline, decimal 10</p></li>
    /// <li>
    /// <p>\r, carriage return, decimal 13</p></li>
    /// <li>
    /// <p>\v, vertical tab, decimal 11</p></li>
    /// <li>
    /// <p>non-breaking space, decimal 160</p></li>
    /// </ul>
    /// <p><code>COMPRESS_WHITE_SPACE</code> also replaces multiple spaces with one space.</p>
    /// <p><b>HTML_ENTITY_DECODE</b></p>
    /// <p>Use this option to replace HTML-encoded characters with unencoded characters. <code>HTML_ENTITY_DECODE</code> performs the following operations:</p>
    /// <ul>
    /// <li>
    /// <p>Replaces <code>(ampersand)quot;</code> with <code>"</code></p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)nbsp;</code> with a non-breaking space, decimal 160</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)lt;</code> with a "less than" symbol</p></li>
    /// <li>
    /// <p>Replaces <code>(ampersand)gt;</code> with <code>&gt;</code></p></li>
    /// <li>
    /// <p>Replaces characters that are represented in hexadecimal format, <code>(ampersand)#xhhhh;</code>, with the corresponding characters</p></li>
    /// <li>
    /// <p>Replaces characters that are represented in decimal format, <code>(ampersand)#nnnn;</code>, with the corresponding characters</p></li>
    /// </ul>
    /// <p><b>LOWERCASE</b></p>
    /// <p>Use this option to convert uppercase letters (A-Z) to lowercase (a-z).</p>
    /// <p><b>URL_DECODE</b></p>
    /// <p>Use this option to decode a URL-encoded value.</p>
    /// <p><b>NONE</b></p>
    /// <p>Specify <code>NONE</code> if you don't want to perform any text transformations.</p>
    pub fn get_text_transformation(&self) -> &::std::option::Option<crate::types::TextTransformation> {
        &self.text_transformation
    }
    /// Consumes the builder and constructs a [`XssMatchTuple`](crate::types::XssMatchTuple).
    /// This method will fail if any of the following fields are not set:
    /// - [`text_transformation`](crate::types::builders::XssMatchTupleBuilder::text_transformation)
    pub fn build(self) -> ::std::result::Result<crate::types::XssMatchTuple, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::XssMatchTuple {
            field_to_match: self.field_to_match,
            text_transformation: self.text_transformation.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "text_transformation",
                    "text_transformation was not specified but it is required when building XssMatchTuple",
                )
            })?,
        })
    }
}

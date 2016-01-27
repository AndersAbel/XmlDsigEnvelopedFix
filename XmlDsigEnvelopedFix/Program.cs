using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace XmlDsigEnvelopedFix
{
    using static Console;

    class Program
    {

        static void Main(string[] args)
        {
            var xml = "<xml><a ID=\"foo\"><content>foo-content</content><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" /></a><a ID=\"bar\"><content>bar-content</content><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" /></a></xml>";

            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(xml);

            var key = new RSACryptoServiceProvider();

            var sign = new SignedXml(xmlDocument);
            var reference2 = new Reference("#bar");
            reference2.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            sign.AddReference(reference2);
            sign.SigningKey = key;
            sign.ComputeSignature();
            var barNode = (XmlElement)xmlDocument.SelectSingleNode("//*[@ID=\"bar\"]");
            barNode.AppendChild(xmlDocument.ImportNode(sign.GetXml(), true));

            var barSignature = barNode.ChildNodes.OfType<XmlElement>()
                .Single(x => x.LocalName == "Signature" && x.HasChildNodes);

            WriteLine("== Xml document ==");
            WriteLine(xmlDocument.OuterXml);
            WriteLine();

            var verify = new SignedXml(xmlDocument);
            verify.LoadXml(barSignature);
            WriteLine("Check Signature: " + verify.CheckSignature(key));

            WriteLine();
            WriteLine("Reloading SignedXml and fixing signature index...");
            verify.LoadXml(barSignature);
            FixSignatureIndex(verify, barSignature);
            WriteLine("Check Signature: " + verify.CheckSignature(key));

            ReadLine();
        }

        private static void FixSignatureIndex(SignedXml sXml, XmlElement signatureElement)
        {
            Transform transform = null;
            foreach (var t in ((Reference)sXml.SignedInfo.References[0]).TransformChain)
            {
                if (t is XmlDsigEnvelopedSignatureTransform)
                {
                    transform = (XmlDsigEnvelopedSignatureTransform)t;
                    break;
                }
            }

            var _signaturePosition = typeof(XmlDsigEnvelopedSignatureTransform)
                .GetField("_signaturePosition", BindingFlags.Instance | BindingFlags.NonPublic);
            WriteLine("Reported SignaturePosition: " + _signaturePosition.GetValue(transform));

            var signaturePosition = typeof(XmlDsigEnvelopedSignatureTransform)
                .GetProperty("SignaturePosition", BindingFlags.Instance | BindingFlags.NonPublic);

            var nsm = new XmlNamespaceManager(signatureElement.OwnerDocument.NameTable);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            var signaturesInParent = signatureElement.ParentNode.SelectNodes(".//ds:Signature", nsm);

            int correctSignaturePosition = 0;
            for (int i = 0; i < signaturesInParent.Count; i++)
            {
                if (signaturesInParent[i] == signatureElement)
                {
                    correctSignaturePosition = i + 1;
                    break;
                }
            }

            signaturePosition.SetValue(transform, correctSignaturePosition);

            WriteLine("Corrected signature position: " + correctSignaturePosition);
        }
    }
}

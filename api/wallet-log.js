module.exports = async (req, res) => {
  if (req.method === 'POST') {
    console.log('[PassKit] logs:', JSON.stringify(req.body));
    return res.status(200).end();
  }
  return res.status(405).end();
};

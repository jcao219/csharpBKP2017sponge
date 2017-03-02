namespace Hello 
{
    class Program
    {
        static Hasher hasher = new Hasher();
        static void Main(string[] args)
        {
            System.Console.Write("S: ");
            string input = System.Console.ReadLine();
            System.Console.WriteLine("H: {0}", hasher.Hash(input));
        }
    }
}
